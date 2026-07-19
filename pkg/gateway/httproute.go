package gateway

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1listers "k8s.io/client-go/listers/core/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewaylistersv1 "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
)

// HCMFilterConfig describes an HCM-level HTTP filter required by a route rule,
// together with any upstream cluster that must be provisioned to support it.
// It is returned by translateHTTPRouteToEnvoyRoutes and consumed by gateway.go
// (cluster provisioning) and listener.go (HCM filter installation).
type HCMFilterConfig struct {
	// FilterName is the Envoy well-known filter name; also used as the
	// TypedPerFilterConfig map key.
	FilterName string
	// BackendRef, if non-nil, identifies the upstream Service to provision a
	// cluster for.
	BackendRef *gatewayv1.BackendObjectReference
	BackendNs  string
	// EnableHTTP2 requests H2 on the upstream cluster (required for gRPC backends).
	EnableHTTP2 bool
	// buildHCMFilter constructs the Envoy HCM HttpFilter proto for this filter.
	buildHCMFilter func() (*hcm.HttpFilter, error)
	// buildDisabledPerRouteConfig, if non-nil, returns the TypedPerFilterConfig
	// entry to stamp onto routes that should bypass this HCM filter.
	buildDisabledPerRouteConfig func() (*anypb.Any, error)
}

// ruleFilterState accumulates the Envoy-side effects of translating all filters
// on a single HTTPRoute rule.
type ruleFilterState struct {
	// redirect, if non-nil, replaces the rule's forwarding action with a redirect.
	redirect *routev3.RedirectAction
	// reqHeadersToAdd / reqHeadersToRemove mutate request headers on every route
	// produced for this rule.
	reqHeadersToAdd    []*corev3.HeaderValueOption
	reqHeadersToRemove []string
	// typedPerFilterConfig holds per-route filter config entries to stamp onto
	// every Envoy route produced for this rule.
	typedPerFilterConfig map[string]*anypb.Any
	// hcmFilters holds HCM-level filter requirements arising from this rule.
	hcmFilters []HCMFilterConfig
	// resolvedRefsErr, if non-nil, overrides the route's ResolvedRefs condition.
	resolvedRefsErr *metav1.Condition
}

// merge folds other into the receiver, with "last writer wins" for redirect and
// resolvedRefsErr.
func (s *ruleFilterState) merge(other ruleFilterState) {
	if other.redirect != nil {
		s.redirect = other.redirect
	}
	s.reqHeadersToAdd = append(s.reqHeadersToAdd, other.reqHeadersToAdd...)
	s.reqHeadersToRemove = append(s.reqHeadersToRemove, other.reqHeadersToRemove...)
	for k, v := range other.typedPerFilterConfig {
		if s.typedPerFilterConfig == nil {
			s.typedPerFilterConfig = make(map[string]*anypb.Any)
		}
		s.typedPerFilterConfig[k] = v
	}
	s.hcmFilters = append(s.hcmFilters, other.hcmFilters...)
	if other.resolvedRefsErr != nil {
		s.resolvedRefsErr = other.resolvedRefsErr
	}
}

// translateRuleFilters translates every filter in a single HTTPRoute rule into
// a ruleFilterState.  On the first unsupported filter type it returns a non-empty
// unsupportedType and stops processing further filters.
func translateRuleFilters(
	filters []gatewayv1.HTTPRouteFilter,
	routeNs string,
	generation int64,
	svcLister corev1listers.ServiceLister,
) (state ruleFilterState, unsupportedType gatewayv1.HTTPRouteFilterType) {
	for _, filter := range filters {
		switch filter.Type {
		case gatewayv1.HTTPRouteFilterRequestRedirect:
			if filter.RequestRedirect != nil {
				state.merge(translateRequestRedirectFilter(filter.RequestRedirect))
				// Per spec only one redirect per rule is valid; stop processing.
				return
			}
		case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
			if filter.RequestHeaderModifier != nil {
				state.merge(translateRequestHeaderModifierFilter(filter.RequestHeaderModifier))
			}
		case gatewayv1.HTTPRouteFilterExternalAuth:
			if filter.ExternalAuth != nil {
				state.merge(translateExternalAuthFilter(filter.ExternalAuth, routeNs, generation, svcLister))
			}
		default:
			return ruleFilterState{}, filter.Type
		}
	}
	return
}

// translateRequestRedirectFilter translates a RequestRedirect filter.
func translateRequestRedirectFilter(f *gatewayv1.HTTPRequestRedirectFilter) ruleFilterState {
	redirectAction := &routev3.RedirectAction{}
	if f.Hostname != nil {
		redirectAction.HostRedirect = string(*f.Hostname)
	}
	if f.StatusCode != nil {
		switch *f.StatusCode {
		case 301:
			redirectAction.ResponseCode = routev3.RedirectAction_MOVED_PERMANENTLY
		case 302:
			redirectAction.ResponseCode = routev3.RedirectAction_FOUND
		case 303:
			redirectAction.ResponseCode = routev3.RedirectAction_SEE_OTHER
		case 307:
			redirectAction.ResponseCode = routev3.RedirectAction_TEMPORARY_REDIRECT
		case 308:
			redirectAction.ResponseCode = routev3.RedirectAction_PERMANENT_REDIRECT
		default:
			redirectAction.ResponseCode = routev3.RedirectAction_MOVED_PERMANENTLY
		}
	} else {
		// Gateway API defaults to 302.
		redirectAction.ResponseCode = routev3.RedirectAction_FOUND
	}
	return ruleFilterState{redirect: redirectAction}
}

// translateRequestHeaderModifierFilter translates a RequestHeaderModifier filter.
func translateRequestHeaderModifierFilter(f *gatewayv1.HTTPHeaderFilter) ruleFilterState {
	var state ruleFilterState
	for _, header := range f.Set {
		state.reqHeadersToAdd = append(state.reqHeadersToAdd, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: string(header.Name), Value: header.Value},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	for _, header := range f.Add {
		state.reqHeadersToAdd = append(state.reqHeadersToAdd, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: string(header.Name), Value: header.Value},
			AppendAction: corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
		})
	}
	state.reqHeadersToRemove = append(state.reqHeadersToRemove, f.Remove...)
	return state
}

// translateExternalAuthFilter translates an ExternalAuth filter. It validates
// that the referenced backend service exists before building any configuration.
func translateExternalAuthFilter(
	f *gatewayv1.HTTPExternalAuthFilter,
	routeNs string,
	generation int64,
	svcLister corev1listers.ServiceLister,
) ruleFilterState {
	authNs := routeNs
	if f.BackendRef.Namespace != nil {
		authNs = string(*f.BackendRef.Namespace)
	}
	if _, err := svcLister.Services(authNs).Get(string(f.BackendRef.Name)); err != nil {
		cond := createFailureCondition(
			gatewayv1.RouteReasonBackendNotFound,
			fmt.Sprintf("ExternalAuth backend %s/%s not found", authNs, f.BackendRef.Name),
			generation,
		)
		return ruleFilterState{resolvedRefsErr: &cond}
	}

	backendRef := gatewayv1.BackendRef{BackendObjectReference: f.BackendRef}
	clusterName, err := backendRefToClusterName(routeNs, backendRef)
	if err != nil {
		cond := createFailureCondition(gatewayv1.RouteReasonBackendNotFound, err.Error(), generation)
		return ruleFilterState{resolvedRefsErr: &cond}
	}

	// Per-route config: enable ext_authz on this specific route.
	extAuthzPerRoute := &extauthzv3.ExtAuthzPerRoute{
		Override: &extauthzv3.ExtAuthzPerRoute_CheckSettings{CheckSettings: &extauthzv3.CheckSettings{}},
	}
	perRouteAny, err := anypb.New(extAuthzPerRoute)
	if err != nil {
		// Programming error; skip auth without crashing.
		return ruleFilterState{}
	}

	cfg := HCMFilterConfig{
		FilterName:  wellknown.HTTPExternalAuthorization,
		BackendRef:  &f.BackendRef,
		BackendNs:   routeNs,
		EnableHTTP2: f.ExternalAuthProtocol == gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
		buildHCMFilter: func() (*hcm.HttpFilter, error) {
			return buildExtAuthzHCMFilter(clusterName, f)
		},
		buildDisabledPerRouteConfig: func() (*anypb.Any, error) {
			return anypb.New(&extauthzv3.ExtAuthzPerRoute{
				Override: &extauthzv3.ExtAuthzPerRoute_Disabled{Disabled: true},
			})
		},
	}

	return ruleFilterState{
		typedPerFilterConfig: map[string]*anypb.Any{
			wellknown.HTTPExternalAuthorization: perRouteAny,
		},
		hcmFilters: []HCMFilterConfig{cfg},
	}
}

// buildExtAuthzHCMFilter builds the HCM-level ext_authz HttpFilter from an
// ExternalAuth filter spec. It is called via HCMFilterConfig.buildHCMFilter so
// that all ExternalAuth-specific Envoy logic is co-located with the rest of the
// ExternalAuth translation.
func buildExtAuthzHCMFilter(clusterName string, f *gatewayv1.HTTPExternalAuthFilter) (*hcm.HttpFilter, error) {
	extAuthz := &extauthzv3.ExtAuthz{
		TransportApiVersion: corev3.ApiVersion_V3,
	}
	switch f.ExternalAuthProtocol {
	case gatewayv1.HTTPRouteExternalAuthGRPCProtocol:
		extAuthz.Services = &extauthzv3.ExtAuthz_GrpcService{
			GrpcService: &corev3.GrpcService{
				TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: clusterName},
				},
			},
		}
		if f.GRPCAuthConfig != nil && len(f.GRPCAuthConfig.AllowedRequestHeaders) > 0 {
			extAuthz.AllowedHeaders = stringsToListStringMatcher(f.GRPCAuthConfig.AllowedRequestHeaders)
		}
	case gatewayv1.HTTPRouteExternalAuthHTTPProtocol:
		httpSvc := &extauthzv3.HttpService{
			ServerUri: &corev3.HttpUri{
				Uri:              fmt.Sprintf("http://%s", clusterName),
				HttpUpstreamType: &corev3.HttpUri_Cluster{Cluster: clusterName},
				Timeout:          durationpb.New(5 * time.Second),
			},
		}
		if f.HTTPAuthConfig != nil {
			if f.HTTPAuthConfig.Path != "" {
				httpSvc.PathPrefix = f.HTTPAuthConfig.Path
			}
			if len(f.HTTPAuthConfig.AllowedRequestHeaders) > 0 {
				httpSvc.AuthorizationRequest = &extauthzv3.AuthorizationRequest{
					AllowedHeaders: stringsToListStringMatcher(f.HTTPAuthConfig.AllowedRequestHeaders),
				}
			}
			if len(f.HTTPAuthConfig.AllowedResponseHeaders) > 0 {
				httpSvc.AuthorizationResponse = &extauthzv3.AuthorizationResponse{
					AllowedUpstreamHeaders: stringsToListStringMatcher(f.HTTPAuthConfig.AllowedResponseHeaders),
				}
			}
		}
		extAuthz.Services = &extauthzv3.ExtAuthz_HttpService{HttpService: httpSvc}
	}
	if f.ForwardBody != nil && f.ForwardBody.MaxSize > 0 {
		extAuthz.WithRequestBody = &extauthzv3.BufferSettings{MaxRequestBytes: uint32(f.ForwardBody.MaxSize)}
	}
	extAuthzAny, err := anypb.New(extAuthz)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ext_authz filter: %w", err)
	}
	return &hcm.HttpFilter{
		Name:       wellknown.HTTPExternalAuthorization,
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: extAuthzAny},
	}, nil
}

// translateHTTPRouteToEnvoyRoutes translates a full HTTPRoute into a slice of
// Envoy Routes.  It also returns:
//   - hcmFilterConfigs: one entry per HCM-level filter required by the route's
//     rules (e.g. ext_authz); the caller provisions the corresponding clusters
//     and installs the filters in the listener's HCM.
//   - validBackendRefs: the resolved upstream backend refs; the caller provisions
//     their Envoy clusters.
//   - conditions: ResolvedRefs (and optionally PartiallyInvalid) status conditions.
func translateHTTPRouteToEnvoyRoutes(
	httpRoute *gatewayv1.HTTPRoute,
	serviceLister corev1listers.ServiceLister,
	referenceGrantLister gatewaylistersv1.ReferenceGrantLister,
) ([]*routev3.Route, []HCMFilterConfig, []gatewayv1.BackendRef, []metav1.Condition) {

	var envoyRoutes []*routev3.Route
	var allHCMFilterConfigs []HCMFilterConfig
	var allValidBackendRefs []gatewayv1.BackendRef
	resolvedRefsCondition := createSuccessCondition(httpRoute.Generation)

	totalRules := len(httpRoute.Spec.Rules)
	var droppedRuleMessages []string

	for ruleIndex, rule := range httpRoute.Spec.Rules {
		filterState, unsupportedType := translateRuleFilters(
			rule.Filters, httpRoute.Namespace, httpRoute.Generation, serviceLister,
		)
		if unsupportedType != "" {
			droppedRuleMessages = append(droppedRuleMessages,
				fmt.Sprintf("rule[%d] has unsupported filter type %q", ruleIndex, unsupportedType))
			continue
		}

		if filterState.resolvedRefsErr != nil {
			resolvedRefsCondition = *filterState.resolvedRefsErr
		}

		allHCMFilterConfigs = append(allHCMFilterConfigs, filterState.hcmFilters...)

		buildRoutesForRule := func(match gatewayv1.HTTPRouteMatch, matchIndex int) {
			routeMatch, matchCondition := translateHTTPRouteMatch(match, httpRoute.Generation)
			if matchCondition.Status == metav1.ConditionFalse {
				resolvedRefsCondition = matchCondition
				return
			}

			envoyRoute := &routev3.Route{
				Name:                   fmt.Sprintf("%s-%s-rule%d-match%d", httpRoute.Namespace, httpRoute.Name, ruleIndex, matchIndex),
				Match:                  routeMatch,
				RequestHeadersToAdd:    filterState.reqHeadersToAdd,
				RequestHeadersToRemove: filterState.reqHeadersToRemove,
				TypedPerFilterConfig:   filterState.typedPerFilterConfig,
			}

			if filterState.redirect != nil {
				envoyRoute.Action = &routev3.Route_Redirect{Redirect: filterState.redirect}
			} else {
				routeAction, validBackends, err := buildHTTPRouteAction(
					httpRoute.Namespace,
					rule.BackendRefs,
					serviceLister,
					referenceGrantLister,
				)
				var controllerErr *ControllerError
				if errors.As(err, &controllerErr) {
					resolvedRefsCondition = createFailureCondition(gatewayv1.RouteConditionReason(controllerErr.Reason), controllerErr.Message, httpRoute.Generation)
					envoyRoute.Action = &routev3.Route_DirectResponse{
						DirectResponse: &routev3.DirectResponseAction{Status: 500},
					}
				} else {
					allValidBackendRefs = append(allValidBackendRefs, validBackends...)
					envoyRoute.Action = &routev3.Route_Route{Route: routeAction}
				}
			}
			envoyRoutes = append(envoyRoutes, envoyRoute)
		}

		if len(rule.Matches) == 0 {
			buildRoutesForRule(gatewayv1.HTTPRouteMatch{}, 0)
		} else {
			for matchIndex, match := range rule.Matches {
				buildRoutesForRule(match, matchIndex)
			}
		}
	}

	invalidRuleCount := len(droppedRuleMessages)
	if invalidRuleCount > 0 && invalidRuleCount == totalRules {
		msg := fmt.Sprintf("no rules could be translated: %s", strings.Join(droppedRuleMessages, "; "))
		return nil, nil, nil, []metav1.Condition{
			createFailureCondition(gatewayv1.RouteReasonUnsupportedValue, msg, httpRoute.Generation),
		}
	}

	conditions := []metav1.Condition{resolvedRefsCondition}
	if invalidRuleCount > 0 {
		msg := fmt.Sprintf("Dropped Rule(s): %s", strings.Join(droppedRuleMessages, "; "))
		conditions = append(conditions, createPartiallyInvalidCondition(msg, httpRoute.Generation))
	}
	return envoyRoutes, allHCMFilterConfigs, allValidBackendRefs, conditions
}

// buildHTTPRouteAction returns an action, a list of *valid* BackendRefs, and a structured error.
func buildHTTPRouteAction(namespace string, backendRefs []gatewayv1.HTTPBackendRef, serviceLister corev1listers.ServiceLister, referenceGrantLister gatewaylistersv1.ReferenceGrantLister) (*routev3.RouteAction, []gatewayv1.BackendRef, error) {
	weightedClusters := &routev3.WeightedCluster{}
	var validBackendRefs []gatewayv1.BackendRef

	for _, httpBackendRef := range backendRefs {
		backendRef := httpBackendRef.BackendRef

		ns := namespace
		if backendRef.Namespace != nil {
			ns = string(*backendRef.Namespace)
		}

		// If it's a cross-namespace reference, we must check for a ReferenceGrant.
		if ns != namespace {
			from := gatewayv1.ReferenceGrantFrom{
				Group:     gatewayv1.GroupName,
				Kind:      "HTTPRoute",
				Namespace: gatewayv1.Namespace(namespace),
			}
			to := gatewayv1.ReferenceGrantTo{
				Group: "", // Core group for Service
				Kind:  "Service",
				Name:  &backendRef.Name,
			}

			if !isCrossNamespaceRefAllowed(from, to, ns, referenceGrantLister) {
				// The reference is not permitted.
				return nil, nil, &ControllerError{
					Reason:  string(gatewayv1.RouteReasonRefNotPermitted),
					Message: "permission error",
				}
			}
		}

		if _, err := serviceLister.Services(ns).Get(string(backendRef.Name)); err != nil {
			return nil, nil, &ControllerError{
				Reason:  string(gatewayv1.RouteReasonBackendNotFound),
				Message: "backend not found",
			}
		}
		clusterName, err := backendRefToClusterName(namespace, backendRef)
		if err != nil {
			return nil, nil, err
		}

		weight := int32(1)
		if httpBackendRef.Weight != nil {
			weight = *httpBackendRef.Weight
		}
		if weight == 0 {
			continue
		}
		validBackendRefs = append(validBackendRefs, backendRef)
		weightedClusters.Clusters = append(weightedClusters.Clusters, &routev3.WeightedCluster_ClusterWeight{
			Name:   clusterName,
			Weight: &wrapperspb.UInt32Value{Value: uint32(weight)},
		})
	}

	if len(weightedClusters.Clusters) == 0 {
		return nil, nil, &ControllerError{Reason: string(gatewayv1.RouteReasonUnsupportedValue), Message: "no valid backends provided with a weight > 0"}
	}

	var action *routev3.RouteAction
	if len(weightedClusters.Clusters) == 1 {
		action = &routev3.RouteAction{ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: weightedClusters.Clusters[0].Name}}
	} else {
		action = &routev3.RouteAction{ClusterSpecifier: &routev3.RouteAction_WeightedClusters{WeightedClusters: weightedClusters}}
	}

	return action, validBackendRefs, nil
}

// translateHTTPRouteMatch translates a Gateway API HTTPRouteMatch into an Envoy RouteMatch.
// It returns the result and a condition indicating success or failure.
func translateHTTPRouteMatch(match gatewayv1.HTTPRouteMatch, generation int64) (*routev3.RouteMatch, metav1.Condition) {
	routeMatch := &routev3.RouteMatch{}

	if match.Path != nil {
		pathType := gatewayv1.PathMatchPathPrefix
		if match.Path.Type != nil {
			pathType = *match.Path.Type
		}
		if match.Path.Value == nil {
			msg := "path match value cannot be nil"
			return nil, createFailureCondition(gatewayv1.RouteReasonUnsupportedValue, msg, generation)
		}
		pathValue := *match.Path.Value

		switch pathType {
		case gatewayv1.PathMatchExact:
			routeMatch.PathSpecifier = &routev3.RouteMatch_Path{Path: pathValue}
		case gatewayv1.PathMatchPathPrefix:
			if pathValue == "/" {
				routeMatch.PathSpecifier = &routev3.RouteMatch_Prefix{Prefix: "/"}
			} else {
				path := strings.TrimSuffix(pathValue, "/")
				routeMatch.PathSpecifier = &routev3.RouteMatch_PathSeparatedPrefix{PathSeparatedPrefix: path}
			}
		case gatewayv1.PathMatchRegularExpression:
			routeMatch.PathSpecifier = &routev3.RouteMatch_SafeRegex{
				SafeRegex: &matcherv3.RegexMatcher{
					EngineType: &matcherv3.RegexMatcher_GoogleRe2{GoogleRe2: &matcherv3.RegexMatcher_GoogleRE2{}},
					Regex:      pathValue,
				},
			}
		default:
			msg := fmt.Sprintf("unsupported path match type: %s", pathType)
			return nil, createFailureCondition(gatewayv1.RouteReasonUnsupportedValue, msg, generation)
		}
	} else {
		// As per Gateway API spec, a nil path match defaults to matching everything.
		routeMatch.PathSpecifier = &routev3.RouteMatch_Prefix{Prefix: "/"}
	}

	// Translate Header Matches
	for _, headerMatch := range match.Headers {
		headerMatcher := &routev3.HeaderMatcher{
			Name: string(headerMatch.Name),
		}
		matchType := gatewayv1.HeaderMatchExact
		if headerMatch.Type != nil {
			matchType = *headerMatch.Type
		}

		switch matchType {
		case gatewayv1.HeaderMatchExact:
			headerMatcher.HeaderMatchSpecifier = &routev3.HeaderMatcher_StringMatch{
				StringMatch: &matcherv3.StringMatcher{
					MatchPattern: &matcherv3.StringMatcher_Exact{Exact: headerMatch.Value},
				},
			}
		case gatewayv1.HeaderMatchRegularExpression:
			headerMatcher.HeaderMatchSpecifier = &routev3.HeaderMatcher_SafeRegexMatch{
				SafeRegexMatch: &matcherv3.RegexMatcher{
					EngineType: &matcherv3.RegexMatcher_GoogleRe2{GoogleRe2: &matcherv3.RegexMatcher_GoogleRE2{}},
					Regex:      headerMatch.Value,
				},
			}
		default:
			msg := fmt.Sprintf("unsupported header match type: %s", matchType)
			return nil, createFailureCondition(gatewayv1.RouteReasonUnsupportedValue, msg, generation)
		}
		routeMatch.Headers = append(routeMatch.Headers, headerMatcher)
	}

	// Translate Query Parameter Matches
	for _, queryMatch := range match.QueryParams {
		// Gateway API only supports "Exact" match for query parameters.
		queryMatcher := &routev3.QueryParameterMatcher{
			Name: string(queryMatch.Name),
			QueryParameterMatchSpecifier: &routev3.QueryParameterMatcher_StringMatch{
				StringMatch: &matcherv3.StringMatcher{
					MatchPattern: &matcherv3.StringMatcher_Exact{Exact: queryMatch.Value},
				},
			},
		}
		routeMatch.QueryParameters = append(routeMatch.QueryParameters, queryMatcher)
	}

	// If all translations were successful, return the final object and a success condition.
	return routeMatch, createSuccessCondition(generation)
}

func createSuccessCondition(generation int64) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionResolvedRefs),
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.RouteReasonResolvedRefs),
		Message:            "All references resolved",
		ObservedGeneration: generation,
	}
}

func createFailureCondition(reason gatewayv1.RouteConditionReason, message string, generation int64) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionResolvedRefs),
		Status:             metav1.ConditionFalse,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: generation,
	}
}

func createPartiallyInvalidCondition(message string, generation int64) metav1.Condition {
	return metav1.Condition{
		Type:               string(gatewayv1.RouteConditionPartiallyInvalid),
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.RouteReasonUnsupportedValue),
		Message:            message,
		ObservedGeneration: generation,
	}
}

// stringsToListStringMatcher converts a list of exact header name strings into the
// Envoy ListStringMatcher type used by the ext_authz filter's allowed-headers fields.
func stringsToListStringMatcher(headers []string) *matcherv3.ListStringMatcher {
	patterns := make([]*matcherv3.StringMatcher, 0, len(headers))
	for _, h := range headers {
		patterns = append(patterns, &matcherv3.StringMatcher{
			MatchPattern: &matcherv3.StringMatcher_Exact{Exact: h},
		})
	}
	return &matcherv3.ListStringMatcher{Patterns: patterns}
}

// sortRoutes is the definitive sorter for Envoy routes based on Gateway API precedence.
func sortRoutes(routes []*routev3.Route) {
	sort.Slice(routes, func(i, j int) bool {
		matchI := routes[i].GetMatch()
		matchJ := routes[j].GetMatch()

		// De-prioritize the catch-all route, ensuring it's always last.
		isCatchAllI := isCatchAll(matchI)
		isCatchAllJ := isCatchAll(matchJ)

		if isCatchAllI != isCatchAllJ {
			// If I is the catch-all, it should come after J (return false).
			// If J is the catch-all, it should come after I (return true).
			return isCatchAllJ
		}

		// Precedence Rule 1: Exact Path Match vs. Other Path Matches
		isExactPathI := matchI.GetPath() != ""
		isExactPathJ := matchJ.GetPath() != ""
		if isExactPathI != isExactPathJ {
			return isExactPathI // Exact path is higher precedence
		}

		// Precedence Rule 2: Longest Prefix Match
		prefixI := getPathMatchValue(matchI)
		prefixJ := getPathMatchValue(matchJ)

		if len(prefixI) != len(prefixJ) {
			return len(prefixI) > len(prefixJ) // Longer prefix is higher precedence
		}

		// Precedence Rule 3: Number of Header Matches
		headerCountI := len(matchI.GetHeaders())
		headerCountJ := len(matchJ.GetHeaders())
		if headerCountI != headerCountJ {
			return headerCountI > headerCountJ // More headers is higher precedence
		}

		// Precedence Rule 4: Number of Query Param Matches
		queryCountI := len(matchI.GetQueryParameters())
		queryCountJ := len(matchJ.GetQueryParameters())
		if queryCountI != queryCountJ {
			return queryCountI > queryCountJ // More query params is higher precedence
		}

		// If all else is equal, maintain original order (stable sort)
		return false
	})
}

// getPathMatchValue is a helper to extract the path string for comparison.
func getPathMatchValue(match *routev3.RouteMatch) string {
	if match.GetPath() != "" {
		return match.GetPath()
	}
	if match.GetPrefix() != "" {
		return match.GetPrefix()
	}
	if match.GetPathSeparatedPrefix() != "" {
		return match.GetPathSeparatedPrefix()
	}
	if sr := match.GetSafeRegex(); sr != nil { // Regex Match (used for other PathPrefix)
		// This correctly handles the output of translateHTTPRouteMatch.
		regex := sr.GetRegex()
		// Remove the trailing regex that matches subpaths.
		path := strings.TrimSuffix(regex, "(/.*)?")
		// Remove the quoting added by regexp.QuoteMeta.
		path = strings.ReplaceAll(path, `\`, "")
		return path
	}
	return ""
}

// isCatchAll determines if a route match is a generic "catch-all" rule.
// A catch-all matches all paths ("/") and has no other specific conditions.
func isCatchAll(match *routev3.RouteMatch) bool {
	if match == nil {
		return false
	}
	// It's a catch-all if the path match is for "/" AND there are no other constraints.
	isRootPrefix := match.GetPrefix() == "/"
	hasNoHeaders := len(match.GetHeaders()) == 0
	hasNoParams := len(match.GetQueryParameters()) == 0

	return isRootPrefix && hasNoHeaders && hasNoParams
}
