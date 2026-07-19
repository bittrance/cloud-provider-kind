package gateway

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/utils/ptr"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// --- mock service lister helpers ---

type mockServiceNamespaceLister struct {
	services map[string]*corev1.Service
}

func (m *mockServiceNamespaceLister) List(_ labels.Selector) ([]*corev1.Service, error) {
	var out []*corev1.Service
	for _, svc := range m.services {
		out = append(out, svc)
	}
	return out, nil
}

func (m *mockServiceNamespaceLister) Get(name string) (*corev1.Service, error) {
	if svc, ok := m.services[name]; ok {
		return svc, nil
	}
	return nil, fmt.Errorf("service %q not found", name)
}

type mockServiceLister struct {
	namespaces map[string]*mockServiceNamespaceLister
}

func (m *mockServiceLister) List(_ labels.Selector) ([]*corev1.Service, error) {
	var out []*corev1.Service
	for _, ns := range m.namespaces {
		svcs, _ := ns.List(labels.Everything())
		out = append(out, svcs...)
	}
	return out, nil
}

func (m *mockServiceLister) Services(namespace string) corev1listers.ServiceNamespaceLister {
	if ns, ok := m.namespaces[namespace]; ok {
		return ns
	}
	return &mockServiceNamespaceLister{} // empty namespace
}

// newMockServiceLister creates a lister pre-populated with the given services.
func newMockServiceLister(svcs ...*corev1.Service) corev1listers.ServiceLister {
	m := &mockServiceLister{namespaces: make(map[string]*mockServiceNamespaceLister)}
	for _, svc := range svcs {
		if _, ok := m.namespaces[svc.Namespace]; !ok {
			m.namespaces[svc.Namespace] = &mockServiceNamespaceLister{services: make(map[string]*corev1.Service)}
		}
		m.namespaces[svc.Namespace].services[svc.Name] = svc
	}
	return m
}

// makeService is a convenience constructor for test services.
func makeService(namespace, name string, port int32) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: port}},
		},
	}
}

// --- helpers to build HTTPRoute rules ---

func makeRuleWithFilters(filters ...gatewayv1.HTTPRouteFilter) gatewayv1.HTTPRouteRule {
	return gatewayv1.HTTPRouteRule{
		Filters: filters,
		BackendRefs: []gatewayv1.HTTPBackendRef{
			{
				BackendRef: gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{
						Name: "svc",
						Port: ptr.To(gatewayv1.PortNumber(80)),
					},
				},
			},
		},
	}
}

func redirectFilter() gatewayv1.HTTPRouteFilter {
	return gatewayv1.HTTPRouteFilter{
		Type:            gatewayv1.HTTPRouteFilterRequestRedirect,
		RequestRedirect: &gatewayv1.HTTPRequestRedirectFilter{},
	}
}

func headerModifierFilter() gatewayv1.HTTPRouteFilter {
	return gatewayv1.HTTPRouteFilter{
		Type: gatewayv1.HTTPRouteFilterRequestHeaderModifier,
		RequestHeaderModifier: &gatewayv1.HTTPHeaderFilter{
			Set: []gatewayv1.HTTPHeader{{Name: "X-Foo", Value: "bar"}},
		},
	}
}

func urlRewriteFilter() gatewayv1.HTTPRouteFilter {
	return gatewayv1.HTTPRouteFilter{
		Type:       gatewayv1.HTTPRouteFilterURLRewrite,
		URLRewrite: &gatewayv1.HTTPURLRewriteFilter{},
	}
}

func responsHeaderFilter() gatewayv1.HTTPRouteFilter {
	return gatewayv1.HTTPRouteFilter{
		Type:                   gatewayv1.HTTPRouteFilterResponseHeaderModifier,
		ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{},
	}
}

func externalAuthHTTPFilter(svcName string) gatewayv1.HTTPRouteFilter {
	return gatewayv1.HTTPRouteFilter{
		Type: gatewayv1.HTTPRouteFilterExternalAuth,
		ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
			ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthHTTPProtocol,
			BackendRef: gatewayv1.BackendObjectReference{
				Name: gatewayv1.ObjectName(svcName),
				Port: ptr.To(gatewayv1.PortNumber(8080)),
			},
			HTTPAuthConfig: &gatewayv1.HTTPAuthConfig{},
		},
	}
}

func externalAuthGRPCFilter(svcName string) gatewayv1.HTTPRouteFilter {
	return gatewayv1.HTTPRouteFilter{
		Type: gatewayv1.HTTPRouteFilterExternalAuth,
		ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
			ExternalAuthProtocol: gatewayv1.HTTPRouteExternalAuthGRPCProtocol,
			BackendRef: gatewayv1.BackendObjectReference{
				Name: gatewayv1.ObjectName(svcName),
				Port: ptr.To(gatewayv1.PortNumber(9191)),
			},
			GRPCAuthConfig: &gatewayv1.GRPCAuthConfig{},
		},
	}
}

func TestTranslateHTTPRouteToEnvoyRoutes_FilterValidation(t *testing.T) {
	svc := makeService("default", "svc", 80)
	svcLister := newMockServiceLister(svc)
	noGrants := newFakeReferenceGrantLister(nil, nil)

	baseRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Generation: 1,
		},
	}

	tests := []struct {
		name                   string
		rules                  []gatewayv1.HTTPRouteRule
		wantRoutes             int
		wantCondTypes          []string
		wantResolvedRefsStatus metav1.ConditionStatus
		wantPartiallyInvalid   bool
	}{
		{
			name: "all supported filters - no PartiallyInvalid",
			rules: []gatewayv1.HTTPRouteRule{
				makeRuleWithFilters(redirectFilter()),
				makeRuleWithFilters(headerModifierFilter()),
			},
			// redirect rules produce routes (redirect action); header-modifier rule also produces a route.
			// Both rules are valid, so at least 2 routes.
			wantRoutes:             2,
			wantResolvedRefsStatus: metav1.ConditionTrue,
			wantPartiallyInvalid:   false,
		},
		{
			name: "single rule with unsupported filter - fully invalid",
			rules: []gatewayv1.HTTPRouteRule{
				makeRuleWithFilters(urlRewriteFilter()),
			},
			wantRoutes:             0,
			wantResolvedRefsStatus: metav1.ConditionFalse,
			wantPartiallyInvalid:   false,
		},
		{
			name: "all rules have unsupported filters - fully invalid",
			rules: []gatewayv1.HTTPRouteRule{
				makeRuleWithFilters(urlRewriteFilter()),
				makeRuleWithFilters(responsHeaderFilter()),
			},
			wantRoutes:             0,
			wantResolvedRefsStatus: metav1.ConditionFalse,
			wantPartiallyInvalid:   false,
		},
		{
			name: "first rule unsupported, second rule supported - partially invalid",
			rules: []gatewayv1.HTTPRouteRule{
				makeRuleWithFilters(urlRewriteFilter()),
				makeRuleWithFilters(redirectFilter()),
			},
			wantRoutes:             1, // only the redirect rule produces a route
			wantResolvedRefsStatus: metav1.ConditionTrue,
			wantPartiallyInvalid:   true,
		},
		{
			name: "first rule supported, second rule unsupported - partially invalid",
			rules: []gatewayv1.HTTPRouteRule{
				makeRuleWithFilters(redirectFilter()),
				makeRuleWithFilters(urlRewriteFilter()),
			},
			wantRoutes:             1,
			wantResolvedRefsStatus: metav1.ConditionTrue,
			wantPartiallyInvalid:   true,
		},
		{
			name: "mix of supported and unsupported across three rules",
			rules: []gatewayv1.HTTPRouteRule{
				makeRuleWithFilters(redirectFilter()),
				makeRuleWithFilters(urlRewriteFilter()),
				makeRuleWithFilters(responsHeaderFilter()),
			},
			wantRoutes:             1,
			wantResolvedRefsStatus: metav1.ConditionTrue,
			wantPartiallyInvalid:   true,
		},
		{
			name:                   "no rules at all",
			rules:                  []gatewayv1.HTTPRouteRule{},
			wantRoutes:             0,
			wantResolvedRefsStatus: metav1.ConditionTrue,
			wantPartiallyInvalid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := baseRoute.DeepCopy()
			route.Spec.Rules = tt.rules

			routes, _, _, conditions := translateHTTPRouteToEnvoyRoutes(route, svcLister, noGrants)

			// Check route count.
			if tt.wantRoutes == 0 && len(routes) != 0 {
				t.Errorf("expected nil/empty routes, got %d", len(routes))
			} else if tt.wantRoutes > 0 && len(routes) != tt.wantRoutes {
				t.Errorf("expected %d routes, got %d", tt.wantRoutes, len(routes))
			}

			// Index conditions by type for easy lookup.
			condByType := make(map[string]metav1.Condition)
			for _, c := range conditions {
				condByType[c.Type] = c
			}

			// Check ResolvedRefs condition.
			resolvedRefs, ok := condByType[string(gatewayv1.RouteConditionResolvedRefs)]
			if !ok {
				t.Fatalf("ResolvedRefs condition missing from returned conditions")
			}
			if resolvedRefs.Status != tt.wantResolvedRefsStatus {
				t.Errorf("ResolvedRefs.Status = %q, want %q", resolvedRefs.Status, tt.wantResolvedRefsStatus)
			}
			if tt.wantResolvedRefsStatus == metav1.ConditionFalse &&
				resolvedRefs.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
				t.Errorf("ResolvedRefs.Reason = %q, want %q", resolvedRefs.Reason, gatewayv1.RouteReasonUnsupportedValue)
			}

			// Check PartiallyInvalid condition.
			partiallyInvalid, hasPICondition := condByType[string(gatewayv1.RouteConditionPartiallyInvalid)]
			if tt.wantPartiallyInvalid {
				if !hasPICondition {
					t.Fatalf("PartiallyInvalid condition missing, want it present")
				}
				if partiallyInvalid.Status != metav1.ConditionTrue {
					t.Errorf("PartiallyInvalid.Status = %q, want True", partiallyInvalid.Status)
				}
				if partiallyInvalid.Reason != string(gatewayv1.RouteReasonUnsupportedValue) {
					t.Errorf("PartiallyInvalid.Reason = %q, want %q", partiallyInvalid.Reason, gatewayv1.RouteReasonUnsupportedValue)
				}
				// Per the spec the message must start with "Dropped Rule".
				if len(partiallyInvalid.Message) < 12 || partiallyInvalid.Message[:12] != "Dropped Rule" {
					t.Errorf("PartiallyInvalid.Message = %q, want prefix \"Dropped Rule\"", partiallyInvalid.Message)
				}
			} else if hasPICondition {
				t.Errorf("PartiallyInvalid condition present but not expected (status=%q)", partiallyInvalid.Status)
			}
		})
	}
}

// TestTranslateHTTPRouteToEnvoyRoutes_ExternalAuth exercises the ExternalAuth filter path:
// verifying that supported ExternalAuth filters are translated into per-route
// TypedPerFilterConfig entries and that the ExternalAuthConfig is returned correctly.
func TestTranslateHTTPRouteToEnvoyRoutes_ExternalAuth(t *testing.T) {
	authSvc := makeService("default", "auth-svc", 8080)
	authGRPCSvc := makeService("default", "auth-grpc-svc", 9191)
	regularSvc := makeService("default", "svc", 80)
	svcLister := newMockServiceLister(authSvc, authGRPCSvc, regularSvc)
	noGrants := newFakeReferenceGrantLister(nil, nil)

	baseRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Generation: 1,
		},
	}

	t.Run("HTTP ExternalAuth filter is treated as supported", func(t *testing.T) {
		route := baseRoute.DeepCopy()
		route.Spec.Rules = []gatewayv1.HTTPRouteRule{
			makeRuleWithFilters(externalAuthHTTPFilter("auth-svc")),
		}
		routes, extAuthConfigs, _, conditions := translateHTTPRouteToEnvoyRoutes(route, svcLister, noGrants)

		if len(routes) != 1 {
			t.Fatalf("expected 1 route, got %d", len(routes))
		}
		if len(extAuthConfigs) != 1 {
			t.Fatalf("expected 1 ExternalAuthConfig, got %d", len(extAuthConfigs))
		}
		cfg := extAuthConfigs[0]
		if cfg.Protocol != gatewayv1.HTTPRouteExternalAuthHTTPProtocol {
			t.Errorf("Protocol = %q, want HTTP", cfg.Protocol)
		}
		if string(cfg.BackendRef.Name) != "auth-svc" {
			t.Errorf("BackendRef.Name = %q, want auth-svc", cfg.BackendRef.Name)
		}

		// The route must have a per-route TypedPerFilterConfig enabling ext_authz.
		if routes[0].TypedPerFilterConfig == nil {
			t.Fatal("expected TypedPerFilterConfig to be set on auth route, got nil")
		}
		if _, ok := routes[0].TypedPerFilterConfig["envoy.filters.http.ext_authz"]; !ok {
			t.Error("expected TypedPerFilterConfig[ext_authz] to be set on auth route")
		}

		// The ResolvedRefs condition should be True (filter is supported).
		condByType := make(map[string]metav1.Condition)
		for _, c := range conditions {
			condByType[c.Type] = c
		}
		resolvedRefs := condByType[string(gatewayv1.RouteConditionResolvedRefs)]
		if resolvedRefs.Status != metav1.ConditionTrue {
			t.Errorf("ResolvedRefs.Status = %q, want True", resolvedRefs.Status)
		}
	})

	t.Run("gRPC ExternalAuth filter is treated as supported", func(t *testing.T) {
		route := baseRoute.DeepCopy()
		route.Spec.Rules = []gatewayv1.HTTPRouteRule{
			makeRuleWithFilters(externalAuthGRPCFilter("auth-grpc-svc")),
		}
		_, extAuthConfigs, _, _ := translateHTTPRouteToEnvoyRoutes(route, svcLister, noGrants)

		if len(extAuthConfigs) != 1 {
			t.Fatalf("expected 1 ExternalAuthConfig, got %d", len(extAuthConfigs))
		}
		if extAuthConfigs[0].Protocol != gatewayv1.HTTPRouteExternalAuthGRPCProtocol {
			t.Errorf("Protocol = %q, want GRPC", extAuthConfigs[0].Protocol)
		}
	})

	t.Run("non-auth route returns no ExternalAuthConfig", func(t *testing.T) {
		route := baseRoute.DeepCopy()
		route.Spec.Rules = []gatewayv1.HTTPRouteRule{
			makeRuleWithFilters(headerModifierFilter()),
		}
		routes, extAuthConfigs, _, _ := translateHTTPRouteToEnvoyRoutes(route, svcLister, noGrants)

		if len(extAuthConfigs) != 0 {
			t.Errorf("expected no ExternalAuthConfigs, got %d", len(extAuthConfigs))
		}
		if len(routes) != 1 {
			t.Fatalf("expected 1 route, got %d", len(routes))
		}
		// The route must NOT have a TypedPerFilterConfig for ext_authz.
		if routes[0].TypedPerFilterConfig != nil {
			if _, ok := routes[0].TypedPerFilterConfig["envoy.filters.http.ext_authz"]; ok {
				t.Error("non-auth route must not have TypedPerFilterConfig[ext_authz]")
			}
		}
	})

	t.Run("missing ExternalAuth backend service sets ResolvedRefs False", func(t *testing.T) {
		route := baseRoute.DeepCopy()
		route.Spec.Rules = []gatewayv1.HTTPRouteRule{
			makeRuleWithFilters(externalAuthGRPCFilter("does-not-exist")),
		}
		// Use a lister that does not contain the auth backend.
		emptyLister := newMockServiceLister(regularSvc)
		routes, extAuthConfigs, _, conditions := translateHTTPRouteToEnvoyRoutes(route, emptyLister, noGrants)

		// No ExternalAuthConfig should be built for a missing service.
		if len(extAuthConfigs) != 0 {
			t.Errorf("expected no ExternalAuthConfigs for missing service, got %d", len(extAuthConfigs))
		}

		// The route should still be emitted (with a 500 direct response or normal action),
		// but ResolvedRefs must be False / BackendNotFound.
		condByType := make(map[string]metav1.Condition)
		for _, c := range conditions {
			condByType[c.Type] = c
		}
		resolvedRefs, ok := condByType[string(gatewayv1.RouteConditionResolvedRefs)]
		if !ok {
			t.Fatal("expected ResolvedRefs condition, got none")
		}
		if resolvedRefs.Status != metav1.ConditionFalse {
			t.Errorf("ResolvedRefs.Status = %q, want False", resolvedRefs.Status)
		}
		if resolvedRefs.Reason != string(gatewayv1.RouteReasonBackendNotFound) {
			t.Errorf("ResolvedRefs.Reason = %q, want BackendNotFound", resolvedRefs.Reason)
		}
		_ = routes
	})

	t.Run("mixed auth and non-auth rules", func(t *testing.T) {
		route := baseRoute.DeepCopy()
		route.Spec.Rules = []gatewayv1.HTTPRouteRule{
			makeRuleWithFilters(externalAuthHTTPFilter("auth-svc")),
			makeRuleWithFilters(headerModifierFilter()),
		}
		routes, extAuthConfigs, _, conditions := translateHTTPRouteToEnvoyRoutes(route, svcLister, noGrants)

		if len(routes) != 2 {
			t.Fatalf("expected 2 routes, got %d", len(routes))
		}
		if len(extAuthConfigs) != 1 {
			t.Fatalf("expected 1 ExternalAuthConfig (from auth rule), got %d", len(extAuthConfigs))
		}

		// Auth route (index 0) should have the ext_authz marker.
		if routes[0].TypedPerFilterConfig == nil {
			t.Fatal("auth route missing TypedPerFilterConfig")
		}
		if _, ok := routes[0].TypedPerFilterConfig["envoy.filters.http.ext_authz"]; !ok {
			t.Error("auth route missing TypedPerFilterConfig[ext_authz]")
		}

		// Non-auth route (index 1) must NOT have the ext_authz marker at this stage.
		// (Disabling non-auth routes is a separate step done in buildEnvoyResourcesForGateway.)
		if routes[1].TypedPerFilterConfig != nil {
			if _, ok := routes[1].TypedPerFilterConfig["envoy.filters.http.ext_authz"]; ok {
				t.Error("non-auth route should not have TypedPerFilterConfig[ext_authz] from translateHTTPRouteToEnvoyRoutes")
			}
		}

		// Both rules are valid, so no PartiallyInvalid condition.
		condByType := make(map[string]metav1.Condition)
		for _, c := range conditions {
			condByType[c.Type] = c
		}
		if _, hasPICondition := condByType[string(gatewayv1.RouteConditionPartiallyInvalid)]; hasPICondition {
			t.Error("unexpected PartiallyInvalid condition for all-supported filters")
		}
	})
}
