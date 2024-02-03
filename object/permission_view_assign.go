package object

import (
	"fmt"
	"strings"
)

type PermissionViewAssign struct {
	Id        int                        `json:"id"`
	Owner     string                     `json:"owner"`
	Code      string                     `json:"code"`
	Users     []string                   `json:"users"`
	Roles     []string                   `json:"roles"`
	Domains   []string                   `json:"domains"`
	Resources []*PermissionViewResources `json:"resources"`
}

func generateSubRule(baseRule string, extraRule string, condition string) string {
	baseRule = strings.TrimSpace(baseRule)
	extraRule = strings.TrimSpace(extraRule)
	condition = strings.TrimSpace(condition)
	subRule := ""
	if baseRule != "" {
		subRule = baseRule
	}

	if extraRule != "" {
		subRule = fmt.Sprintf("%s %s (%s)", baseRule, condition, extraRule)
	}

	return subRule
}

//func generateResourcesMap(prefix string, resources []*PermissionViewResources, resourcesMap map[string]map[string]string) {
//	for _, resource := range resources {
//		keyName := fmt.Sprintf("%s.%s", prefix, resource.Name)
//		resourcesMap[keyName] = map[string]string{"abac_rule": resource.AbacRule, "condition": resource.Condition}
//		if len(resource.Children) > 0 {
//			mark := ""
//			if resource.Type == "array" {
//				mark = "[]"
//			}
//			keyName = keyName + mark
//			generateResourcesMap(keyName, resource.Children, resourcesMap)
//		}
//	}
//}

func generateResourcesMap(prefix string, resources []*PermissionViewResources, resourcesMap map[string]map[string]string) {
	for _, resource := range resources {
		keyName := fmt.Sprintf("%s.%s", prefix, resource.Name)
		resourcesMap[keyName] = map[string]string{"abac_rule": resource.AbacRule, "condition": resource.Condition}
		if len(resource.Children) > 0 {
			mark := ""
			//if resource.Type == "array" {
			//	mark = "[]"
			//}
			if count := strings.Count(resource.Type, "array"); count > 0 {
				mark = strings.Repeat("[]", count)
			}
			keyName = keyName + mark
			generateResourcesMap(keyName, resource.Children, resourcesMap)
		}
	}
}

func getPermissionViewAssignPolicies(permissionViewAssign *PermissionViewAssign, permissionView *PermissionView) [][]string {
	var policies [][]string
	viewResourcesMap := make(map[string]map[string]string, 5)
	viewAssignResourcesMap := make(map[string]map[string]string, 5)
	generateResourcesMap(permissionView.Code, permissionView.Resources, viewResourcesMap)
	generateResourcesMap(permissionViewAssign.Code, permissionViewAssign.Resources, viewAssignResourcesMap)
	domainExist := len(permissionViewAssign.Domains) > 0

	for _, user := range permissionViewAssign.Users {
		for viewAssignResourceKey, viewAssignResourceMap := range viewAssignResourcesMap {
			viewResourceMap, ok := viewResourcesMap[viewAssignResourceKey]
			if !ok {
				continue
			}
			//subRule := fmt.Sprintf("%s %s (%s)", viewResourceMap["abac_rule"], viewAssignResourceMap["condition"], viewAssignResourceMap["abac_rule"])
			subRule := generateSubRule(viewResourceMap["abac_rule"], viewAssignResourceMap["abac_rule"], viewAssignResourceMap["condition"])
			if subRule == "" {
				subRule = "true"
			}
			if domainExist {
				for _, domain := range permissionViewAssign.Domains {
					policies = append(policies, []string{user, domain, subRule, viewAssignResourceKey, "read"})
				}
			} else {
				policies = append(policies, []string{user, subRule, viewAssignResourceKey, "read"})
			}
		}
	}

	for _, role := range permissionViewAssign.Roles {
		for viewAssignResourceKey, viewAssignResourceMap := range viewAssignResourcesMap {
			viewResourceMap, ok := viewResourcesMap[viewAssignResourceKey]
			if !ok {
				continue
			}
			//subRule := fmt.Sprintf("%s %s (%s)", viewResourceMap["abac_rule"], viewAssignResourceMap["condition"], viewAssignResourceMap["abac_rule"])
			subRule := generateSubRule(viewResourceMap["abac_rule"], viewAssignResourceMap["abac_rule"], viewAssignResourceMap["condition"])
			if subRule == "" {
				subRule = "true"
			}
			if domainExist {
				for _, domain := range permissionViewAssign.Domains {
					subRule := fmt.Sprintf("%s %s (%s)", viewResourceMap["abac_rule"], viewAssignResourceMap["condition"], viewAssignResourceMap["abac_rule"])
					policies = append(policies, []string{role, domain, subRule, viewAssignResourceKey, "read"})
				}
			} else {
				policies = append(policies, []string{role, subRule, viewAssignResourceKey, "read"})
			}
		}
	}

	return policies
}

func addPermissionViewAssignPolicies(permissionViewAssign *PermissionViewAssign, permissionView *PermissionView, permission *Permission) {
	policies := getPermissionViewAssignPolicies(permissionViewAssign, permissionView)
	enforcer := getEnforcer(permission)

	_, err := enforcer.AddPolicies(policies)
	if err != nil {
		panic(err)
	}
}

func AddPermissionViewAssign(permissionViewAssign *PermissionViewAssign) (bool, error) {
	affected, err := adapter.Engine.Insert(permissionViewAssign)
	if err != nil {
		return false, err
	}

	if affected != 0 {
		permissionView, err := GetPermissionViewByCode(permissionViewAssign.Owner, permissionViewAssign.Code)
		if err != nil {
			return false, err
		}

		permission := &Permission{
			Users:   permissionViewAssign.Users,
			Roles:   permissionViewAssign.Roles,
			Domains: permissionViewAssign.Domains,
			Adapter: permissionView.Adapter,
			Model:   permissionView.Model,
			Owner:   permissionView.Owner,
		}
		addGroupingPolicies(permission)
		addPermissionViewAssignPolicies(permissionViewAssign, permissionView, permission)

	}

	return affected != 0, nil
}
