// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"fmt"
	"github.com/beego/beego/logs"
	"sort"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/log"
	"github.com/casbin/casbin/v2/model"
	"github.com/casdoor/casdoor/conf"
	xormadapter "github.com/casdoor/xorm-adapter/v3"
)

func getEnforcer(permission *Permission) *casbin.Enforcer {
	tableName := "permission_rule"
	if len(permission.Adapter) != 0 {
		adapterObj, err := getCasbinAdapter(permission.Owner, permission.Adapter)
		if err != nil {
			panic(err)
		}

		if adapterObj != nil && adapterObj.Table != "" {
			tableName = adapterObj.Table
		}
	}
	tableNamePrefix := conf.GetConfigString("tableNamePrefix")
	driverName := conf.GetConfigString("driverName")
	dataSourceName := conf.GetConfigRealDataSourceName(driverName)
	adapter, err := xormadapter.NewAdapterWithTableName(driverName, dataSourceName, tableName, tableNamePrefix, true)
	if err != nil {
		panic(err)
	}

	permissionModel, err := getModel(permission.Owner, permission.Model)
	if err != nil {
		panic(err)
	}

	m := model.Model{}
	if permissionModel != nil {
		m, err = GetBuiltInModel(permissionModel.ModelText)
	} else {
		m, err = GetBuiltInModel("")
	}

	if err != nil {
		panic(err)
	}

	// Init an enforcer instance without specifying a model or adapter.
	// If you specify an adapter, it will load all policies, which is a
	// heavy process that can slow down the application.
	enforcer, err := casbin.NewEnforcer(&log.DefaultLogger{}, false)
	if err != nil {
		panic(err)
	}

	err = enforcer.InitWithModelAndAdapter(m, nil)
	if err != nil {
		panic(err)
	}

	enforcer.SetAdapter(adapter)

	//policyFilterV5 := []string{permission.GetId()}
	//if len(permissionIDs) != 0 {
	//	policyFilterV5 = permissionIDs
	//}

	policyFilter := xormadapter.Filter{
		//V5: policyFilterV5,
	}

	if !HasRoleDefinition(m) {
		policyFilter.Ptype = []string{"p"}
	}

	err = enforcer.LoadFilteredPolicy(policyFilter)
	if err != nil {
		panic(err)
	}

	return enforcer
}
func getPolicies(permission *Permission) [][]string {
	var policies [][]string
	//permissionId := permission.Owner + "/" + permission.Name
	domainExist := len(permission.Domains) > 0

	for _, user := range permission.Users {
		for _, resource := range permission.Resources {
			for _, action := range permission.Actions {
				if domainExist {
					for _, domain := range permission.Domains {
						policies = append(policies, []string{user, domain, resource, strings.ToLower(action)})
					}
				} else {
					policies = append(policies, []string{user, resource, strings.ToLower(action)})
				}
			}
		}
	}

	for _, role := range permission.Roles {
		for _, resource := range permission.Resources {
			for _, action := range permission.Actions {
				if domainExist {
					for _, domain := range permission.Domains {
						policies = append(policies, []string{role, domain, resource, strings.ToLower(action)})
					}
				} else {
					policies = append(policies, []string{role, resource, strings.ToLower(action)})
				}
			}
		}
	}

	return policies
}

func getRolesInRole(roleId string, visited map[string]struct{}) ([]*Role, error) {
	role, err := GetRole(roleId)
	if err != nil {
		return []*Role{}, err
	}

	if role == nil {
		return []*Role{}, nil
	}
	visited[roleId] = struct{}{}

	roles := []*Role{role}
	for _, subRole := range role.Roles {
		if _, ok := visited[subRole]; !ok {
			r, err := getRolesInRole(subRole, visited)
			if err != nil {
				return []*Role{}, err
			}

			roles = append(roles, r...)
		}
	}

	return roles, nil
}

func getGroupingPolicies(permission *Permission) [][]string {
	var groupingPolicies [][]string
	//permissionId := permission.Owner + "/" + permission.Name
	domainExist := len(permission.Domains) > 0
	for _, role := range permission.Roles {
		roleObj, _ := GetRole(role)
		if roleObj != nil {
			for _, subUser := range roleObj.Users {
				if domainExist {
					for _, domain := range permission.Domains {
						groupingPolicies = append(groupingPolicies, []string{subUser, domain, role})
					}
				} else {
					groupingPolicies = append(groupingPolicies, []string{subUser, role})
				}
			}
			for _, subRole := range roleObj.Roles {
				if domainExist {
					for _, domain := range permission.Domains {
						groupingPolicies = append(groupingPolicies, []string{subRole, domain, role})
					}
				} else {
					groupingPolicies = append(groupingPolicies, []string{subRole, role})
				}
			}
		}

	}
	return groupingPolicies
}

func addGroupingPolicies(permission *Permission) {
	enforcer := getEnforcer(permission)
	groupingPolicies := getGroupingPolicies(permission)

	if len(groupingPolicies) > 0 {
		_, err := enforcer.AddGroupingPolicies(groupingPolicies)
		if err != nil {
			panic(err)
		}
	}
}

func addPolicies(permission *Permission) {
	enforcer := getEnforcer(permission)
	policies := getPolicies(permission)

	_, err := enforcer.AddPolicies(policies)
	if err != nil {
		panic(err)
	}
}

func removeGroupingPolicies(permission *Permission) {
	enforcer := getEnforcer(permission)
	groupingPolicies := getGroupingPolicies(permission)

	if len(groupingPolicies) > 0 {
		_, err := enforcer.RemoveGroupingPolicies(groupingPolicies)
		if err != nil {
			panic(err)
		}
	}
}

func removePolicies(permission *Permission) {
	enforcer := getEnforcer(permission)
	policies := getPolicies(permission)

	_, err := enforcer.RemovePolicies(policies)
	if err != nil {
		panic(err)
	}
}

func UrlActionAuthz(permissionRule *PermissionRule, adapters []string) bool {
	var permissions []*Permission
	err := adapter.Engine.In("adapter", adapters).Find(&permissions)
	if err != nil {
		panic(err)
	}
	for _, p := range permissions {
		enforcer := getEnforcer(p)
		request, _ := permissionRule.GetRequest(builtInAdapter, permissionRule.Id)
		allow, err := enforcer.Enforce(request...)
		if err != nil {
			panic(err)
		}
		return allow
	}
	return false
}

type CasbinRequest = []interface{}

func Enforce(permission *Permission, request *CasbinRequest, permissionIds ...string) (bool, error) {
	enforcer := getEnforcer(permission)
	return enforcer.Enforce(*request...)
}

//func BatchEnforce(permission *Permission, requests *[]CasbinRequest, permissionIds ...string) ([]bool, error) {
//	enforcer := getEnforcer(permission)
//	return enforcer.BatchEnforce(*requests)
//}

func BatchEnforce(permissionRules []PermissionRule) []bool {
	allows := make([]bool, len(permissionRules))
	type group struct {
		requests [][]interface{}
		rank     []int
		id       string
	}
	groups := make(map[string]*group)
	for i, permissionRule := range permissionRules {
		r := []interface{}{permissionRule.V0, permissionRule.V1, permissionRule.V2}
		if permissionRule.V3 != "" {
			r = append(r, permissionRule.V3)
		}
		if groups[permissionRule.Id] == nil {
			groups[permissionRule.Id] = &group{}
		}
		groups[permissionRule.Id].requests = append(groups[permissionRule.Id].requests, r)
		groups[permissionRule.Id].rank = append(groups[permissionRule.Id].rank, i)
		groups[permissionRule.Id].id = permissionRule.Id
	}

	keys := make([]string, 0)

	var groupSlice []*group
	for k, _ := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		groupSlice = append(groupSlice, groups[k])
	}

	wg := sync.WaitGroup{}
	wg.Add(len(groups))
	for _, g := range groupSlice {
		permission, _ := GetPermission(g.id)
		enforcer := getEnforcer(permission)
		go func(g *group) {

			defer func() {
				if r := recover(); r != nil {
					var ok bool
					err, ok := r.(error)
					if !ok {
						err = fmt.Errorf("%v", r)
					}
					logs.Error("goroutine panic: %v", err)
					wg.Done()
				}
			}()

			allow, err := enforcer.BatchEnforce(g.requests)
			if err != nil {
				panic(err)
			}

			if len(allow) != len(g.rank) {
				panic("length does not match")
			}

			for k, v := range allow {
				allows[g.rank[k]] = v
			}
			wg.Done()
		}(g)

	}
	wg.Wait()

	return allows
}

func getAllValues(userId string, fn func(enforcer *casbin.Enforcer) []string) []string {
	permissions, _, err := GetPermissionsAndRolesByUser(userId)
	if err != nil {
		panic(err)
	}

	for _, role := range GetAllRoles(userId) {
		permissionsByRole, err := GetPermissionsByRole(role)
		if err != nil {
			panic(err)
		}

		permissions = append(permissions, permissionsByRole...)
	}

	var values []string
	for _, permission := range permissions {
		enforcer := getEnforcer(permission)
		values = append(values, fn(enforcer)...)
	}
	return values
}

func GetAllObjects(userId string) []string {
	return getAllValues(userId, func(enforcer *casbin.Enforcer) []string {
		return enforcer.GetAllObjects()
	})
}

func GetAllActions(userId string) []string {
	return getAllValues(userId, func(enforcer *casbin.Enforcer) []string {
		return enforcer.GetAllActions()
	})
}

func GetAllRoles(userId string) []string {
	roles, err := GetRolesByUser(userId)
	if err != nil {
		panic(err)
	}

	var res []string
	for _, role := range roles {
		res = append(res, role.Name)
	}
	return res
}

func getGroupingPoliciesByPermissions(column []string, role *Role, permissions []*Permission) map[string][][]string {
	var groupingPolicies = make(map[string][][]string, len(permissions))
	for _, p := range permissions {
		//permissionId := p.Owner + "/" + p.Name
		domainExist := len(p.Domains) > 0
		key := p.Adapter + "/" + strings.Join(p.Domains, ",")
		if _, ok := groupingPolicies[key]; ok {
			continue
		}
		for _, v := range column {
			if domainExist {
				for _, domain := range p.Domains {
					groupingPolicies[key] = append(groupingPolicies[key], []string{v, domain, role.Owner + "/" + role.Name})
				}
			} else {
				groupingPolicies[key] = append(groupingPolicies[key], []string{v, role.Owner + "/" + role.Name})
			}
		}
	}

	return groupingPolicies
}

func getPoliciesByPermissions(column []string, permissions []*Permission) map[string][][]string {
	var policies = make(map[string][][]string, len(permissions))
	for _, p := range permissions {
		//permissionId := p.Owner + "/" + p.Name
		domainExist := len(p.Domains) > 0
		key := p.Adapter + "/" + strings.Join(p.Domains, ",")
		//if _, ok := policies[key]; ok {
		//	continue
		//}
		for _, v := range column {
			for _, resource := range p.Resources {
				for _, action := range p.Actions {
					if domainExist {
						for _, domain := range p.Domains {
							policies[key] = append(policies[key], []string{v, domain, resource, strings.ToLower(action)})
						}
					} else {
						policies[key] = append(policies[key], []string{v, resource, strings.ToLower(action)})
					}
				}
			}
		}
	}
	return policies
}

//func operateGroupingPoliciesByPermission(permission *Permission, enforcer *casbin.Enforcer, isAdd bool) {
//	var err error
//	domainExist := len(permission.Domains) > 0
//	for _, role := range permission.Roles {
//		roleObj := GetRole(role)
//		for _, user := range roleObj.Users {
//			if domainExist {
//				for _, domain := range permission.Domains {
//					if isAdd {
//						_, err = enforcer.AddNamedGroupingPolicy("g", user, domain, roleObj.Owner+"/"+roleObj.Name)
//					} else {
//						_, err = enforcer.RemoveNamedGroupingPolicy("g", user, domain, roleObj.Owner+"/"+roleObj.Name)
//					}
//					if err != nil {
//						panic(err)
//					}
//				}
//			} else {
//				if isAdd {
//					_, err = enforcer.AddNamedGroupingPolicy("g", user, roleObj.Owner+"/"+roleObj.Name)
//				} else {
//					_, err = enforcer.RemoveNamedGroupingPolicy("g", user, roleObj.Owner+"/"+roleObj.Name)
//				}
//				if err != nil {
//					panic(err)
//				}
//			}
//		}
//	}
//}
//
//func operatePoliciesByPermission(permission *Permission, enforcer *casbin.Enforcer, isAdd bool, isUser bool) {
//	var err error
//	column := permission.Roles
//	if isUser {
//		column = permission.Users
//	}
//	domainExist := len(permission.Domains) > 0
//	for _, v := range column {
//		for _, resource := range permission.Resources {
//			for _, action := range permission.Actions {
//				if domainExist {
//					for _, domain := range permission.Domains {
//						if isAdd {
//							_, err = enforcer.AddNamedPolicy("p", v, domain, resource, action)
//						} else {
//							_, err = enforcer.RemoveNamedPolicy("p", v, domain, resource, action)
//						}
//						if err != nil {
//							panic(err)
//						}
//					}
//				} else {
//					if isAdd {
//						_, err = enforcer.AddNamedPolicy("p", v, resource, action)
//					} else {
//						_, err = enforcer.RemoveNamedPolicy("p", v, resource, action)
//					}
//					if err != nil {
//						panic(err)
//					}
//				}
//			}
//		}
//	}
//}

func GetBuiltInModel(modelText string) (model.Model, error) {
	if modelText == "" {
		modelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`
		return model.NewModelFromString(modelText)
	} else {
		//cfg, err := config.NewConfigFromText(modelText)
		//if err != nil {
		//	return nil, err
		//}

		// load [policy_definition]
		//policyDefinition := strings.Split(cfg.String("policy_definition::p"), ",")
		//fieldsNum := len(policyDefinition)
		//if fieldsNum > builtInAvailableField {
		//	panic(fmt.Errorf("the maximum policy_definition field number cannot exceed %d", builtInAvailableField))
		//}
		// filled empty field with "" and V5 with "permissionId"
		//for i := builtInAvailableField - fieldsNum; i > 0; i-- {
		//	policyDefinition = append(policyDefinition, "")
		//}
		//policyDefinition = append(policyDefinition, "permissionId")

		m, _ := model.NewModelFromString(modelText)
		//m.AddDef("p", "p", strings.Join(policyDefinition, ","))

		return m, nil
	}
}
