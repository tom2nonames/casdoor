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
	"errors"
	"fmt"
	"github.com/casdoor/casdoor/conf"
	"regexp"
	"strings"

	"github.com/casbin/casbin/v2"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

type Permission struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Description string `xorm:"varchar(100)" json:"description"`

	Users   []string `xorm:"mediumtext" json:"users"`
	Roles   []string `xorm:"mediumtext" json:"roles"`
	Domains []string `xorm:"mediumtext" json:"domains"`

	Model        string   `xorm:"varchar(100)" json:"model"`
	Adapter      string   `xorm:"varchar(100)" json:"adapter"`
	ResourceType string   `xorm:"varchar(100)" json:"resourceType"`
	Resources    []string `xorm:"mediumtext" json:"resources"`
	Actions      []string `xorm:"mediumtext" json:"actions"`
	AbacRule     string   `xorm:"mediumtext" json:"abacRule"`
	Effect       string   `xorm:"varchar(100)" json:"effect"`
	IsEnabled    bool     `json:"isEnabled"`

	Submitter   string `xorm:"varchar(100)" json:"submitter"`
	Approver    string `xorm:"varchar(100)" json:"approver"`
	ApproveTime string `xorm:"varchar(100)" json:"approveTime"`
	State       string `xorm:"varchar(100)" json:"state"`
}

type PermissionRule struct {
	Ptype string `xorm:"varchar(100) index not null default ''" json:"ptype"`
	V0    string `xorm:"varchar(100) index not null default ''" json:"v0"`
	V1    string `xorm:"varchar(100) index not null default ''" json:"v1"`
	V2    string `xorm:"varchar(100) index not null default ''" json:"v2"`
	V3    string `xorm:"varchar(100) index not null default ''" json:"v3"`
	V4    string `xorm:"varchar(100) index not null default ''" json:"v4"`
	V5    string `xorm:"varchar(100) index not null default ''" json:"v5"`
	Id    string `xorm:"varchar(100) index not null default ''" json:"id"`
}

const (
	builtInAvailableField = 5 // Casdoor built-in adapter, use V5 to filter permission, so has 5 available field
	builtInAdapter        = "permission_rule"
)

func (p *Permission) GetId() string {
	return util.GetId(p.Owner, p.Name)
}

func (p *PermissionRule) GetRequest(adapterName string, permissionId string) ([]interface{}, error) {
	request := []interface{}{p.V0, p.V1, p.V2}

	if p.V3 != "" {
		request = append(request, p.V3)
	}

	if p.V4 != "" {
		request = append(request, p.V4)
	}

	return request, nil

	//if adapterName == builtInAdapter {
	//	if p.V5 != "" {
	//		return nil, fmt.Errorf("too many parameters. The maximum parameter number cannot exceed %d", builtInAvailableField)
	//	}
	//	request = append(request, permissionId)
	//	return request, nil
	//} else {
	//	if p.V5 != "" {
	//		request = append(request, p.V5)
	//	}
	//	return request, nil
	//}
}

func GetPermissionCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Permission{})
}

func GetPermissions(owner string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := adapter.Engine.Desc("created_time").Find(&permissions, &Permission{Owner: owner})
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func GetPaginationPermissions(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Permission, error) {
	permissions := []*Permission{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&permissions)
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func getPermission(owner string, name string) (*Permission, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	permission := Permission{Owner: owner, Name: name}
	existed, err := adapter.Engine.Get(&permission)
	if err != nil {
		return &permission, err
	}

	if existed {
		return &permission, nil
	} else {
		return nil, nil
	}
}

func GetPermission(id string) (*Permission, error) {
	owner, name := util.GetOwnerAndNameFromId(id)
	return getPermission(owner, name)
}

// checkPermissionValid verifies if the permission is valid
func checkPermissionValid(permission *Permission) error {
	enforcer := getEnforcer(permission)
	enforcer.EnableAutoSave(false)

	policies := getPolicies(permission)
	_, err := enforcer.AddPolicies(policies)
	if err != nil {
		return err
	}

	if !HasRoleDefinition(enforcer.GetModel()) {
		permission.Roles = []string{}
		return nil
	}

	groupingPolicies := getGroupingPolicies(permission)
	if len(groupingPolicies) > 0 {
		_, err := enforcer.AddGroupingPolicies(groupingPolicies)
		if err != nil {
			return err
		}
	}

	return nil
}

func UpdatePermission(id string, permission *Permission) (bool, error) {
	err := checkPermissionAbacRule(permission)
	if err != nil {
		return false, err
	}
	//checkPermissionValid(permission)
	owner, name := util.GetOwnerAndNameFromId(id)
	oldPermission, err := getPermission(owner, name)
	if oldPermission == nil {
		return false, err
	}

	oldEnforcer := getEnforcer(oldPermission)
	oldIndex := 1
	if len(oldPermission.Domains) > 0 {
		oldIndex = 2
	}

	newEnforcer := getEnforcer(permission)
	//newIndex := 1
	//if len(permission.Domains) > 0 {
	//	newIndex = 2
	//}

	if oldPermission.AbacRule != permission.AbacRule {
		removePolicies(oldPermission)
		addPolicies(permission)
	}

	//If the adapter is modified, move the data to the new adapter
	if oldPermission.Adapter != permission.Adapter {
		permissions := GetPermissionsByAdapterAndDomainsAndRole(oldPermission.Adapter, oldPermission.Domains, "")
		//If only one permission uses the adapter, remove the GroupingPolicy directly.
		if len(permissions) == 1 {
			for _, role := range oldPermission.Roles {
				RemoveGroupingPolicyByDomains(oldEnforcer, oldPermission.Domains, oldIndex, role)
			}
		} else {
			//If there are multiple permissions using the adapter, determine whether the elements in oldPermission.Roles are referenced in other permissions, and if so, do not delete them.
			judgeRepeatRole(oldEnforcer, oldPermission.Roles, oldPermission.Domains, oldIndex, permissions)
		}

		for _, resource := range oldPermission.Resources {
			_, err := oldEnforcer.RemoveFilteredNamedPolicy("p", oldIndex, resource)
			if err != nil {
				panic(err)
			}
		}

		addGroupingPolicies(permission)
		addPolicies(permission)

		affected, err := adapter.Engine.ID(core.PK{owner, name}).AllCols().Update(permission)
		if err != nil {
			return false, err
		}

		return affected != 0, nil
	}

	usersAdded, usersDeleted := util.Arrcmp(oldPermission.Users, permission.Users)
	rolesAdded, rolesDeleted := util.Arrcmp(oldPermission.Roles, permission.Roles)
	domainsAdded, domainsDeleted := util.Arrcmp(oldPermission.Domains, permission.Domains)
	resourcesAdded, resourcesDeleted := util.Arrcmp(oldPermission.Resources, permission.Resources)
	actionsAdded, actionsDeleted := util.Arrcmp(oldPermission.Actions, permission.Actions)

	if len(domainsDeleted) > 0 {
		permissions := GetPermissionsByAdapterAndDomainsAndRole(oldPermission.Adapter, domainsDeleted, "")
		if len(permissions) == 1 {
			for _, role := range oldPermission.Roles {
				RemoveGroupingPolicyByDomains(oldEnforcer, domainsDeleted, oldIndex, role)
			}
		} else {
			judgeRepeatRole(oldEnforcer, oldPermission.Roles, domainsDeleted, oldIndex, permissions)
		}

		for _, domain := range domainsDeleted {
			for _, resource := range oldPermission.Resources {
				_, err := oldEnforcer.RemoveFilteredNamedPolicy("p", oldIndex-1, domain, resource)
				if err != nil {
					panic(err)
				}
			}
		}

		//If permissions are modified and Domains are [] regenerate GroupingPolicies and Policies
		if len(permission.Domains) == 0 {
			addGroupingPolicies(permission)
			addPolicies(permission)
		}

	}

	if len(domainsAdded) > 0 {
		//If oldPermission.Domains was originally [], delete the original GroupingPolicy and Policy after adding the new domain.
		if len(oldPermission.Domains) == 0 {
			permissions := GetPermissionsByAdapterAndDomainsAndRole(oldPermission.Adapter, []string{}, "")
			if len(permissions) == 1 {
				for _, role := range oldPermission.Roles {
					RemoveGroupingPolicyByDomains(oldEnforcer, []string{}, oldIndex, role)
				}
			} else {
				judgeRepeatRole(oldEnforcer, oldPermission.Roles, domainsAdded, oldIndex, permissions)
			}

			for _, resource := range oldPermission.Resources {
				_, err := oldEnforcer.RemoveFilteredNamedPolicy("p", oldIndex, resource)
				if err != nil {
					panic(err)
				}
			}
		}

		permissionMock := &Permission{
			Owner:     permission.Owner,
			Name:      permission.Name,
			Users:     permission.Users,
			Roles:     permission.Roles,
			Domains:   domainsAdded,
			Resources: permission.Resources,
			Actions:   permission.Actions,
			AbacRule:  permission.AbacRule,
		}
		operateGroupingPoliciesByPermission(permissionMock, newEnforcer, true)

		operatePoliciesByPermission(permissionMock, newEnforcer, true, false)
		operatePoliciesByPermission(permissionMock, newEnforcer, true, true)
	}

	if len(usersDeleted) > 0 {
		permissionMock := &Permission{
			Owner:     oldPermission.Owner,
			Name:      oldPermission.Name,
			Users:     usersDeleted,
			Roles:     oldPermission.Roles,
			Resources: oldPermission.Resources,
			Actions:   oldPermission.Actions,
			Domains:   oldPermission.Domains,
			AbacRule:  oldPermission.AbacRule,
		}
		operatePoliciesByPermission(permissionMock, oldEnforcer, false, true)

	}

	if len(usersAdded) > 0 {
		permissionMock := &Permission{
			Owner:     permission.Owner,
			Name:      permission.Name,
			Users:     usersAdded,
			Roles:     permission.Roles,
			Resources: permission.Resources,
			Actions:   permission.Actions,
			Domains:   permission.Domains,
			AbacRule:  permission.AbacRule,
		}
		operatePoliciesByPermission(permissionMock, newEnforcer, true, true)
	}

	if len(rolesDeleted) > 0 {

		for _, role := range rolesDeleted {
			permissions := GetPermissionsByAdapterAndDomainsAndRole(oldPermission.Adapter, oldPermission.Domains, role)
			var num int
			for _, p := range permissions {
				if ok, _ := util.InArray(role, p.Roles); ok {
					num++
					if num > 1 {
						break
					}
				}
			}
			if num <= 1 {
				RemoveGroupingPolicyByDomains(oldEnforcer, oldPermission.Domains, oldIndex, role)
			}
		}

		permissionMock := &Permission{
			Owner:     oldPermission.Owner,
			Name:      oldPermission.Name,
			Users:     oldPermission.Users,
			Roles:     rolesDeleted,
			Resources: oldPermission.Resources,
			Actions:   oldPermission.Actions,
			Domains:   oldPermission.Domains,
			AbacRule:  oldPermission.AbacRule,
		}
		operatePoliciesByPermission(permissionMock, oldEnforcer, false, false)

	}

	if len(rolesAdded) > 0 {

		permissionMock := &Permission{
			Owner:     permission.Owner,
			Name:      permission.Name,
			Roles:     rolesAdded,
			Domains:   permission.Domains,
			Resources: permission.Resources,
			Actions:   permission.Actions,
			AbacRule:  permission.AbacRule,
		}

		operateGroupingPoliciesByPermission(permissionMock, newEnforcer, true)

		operatePoliciesByPermission(permissionMock, newEnforcer, true, false)

	}

	if len(resourcesDeleted) > 0 {
		for _, resource := range resourcesDeleted {
			_, err := oldEnforcer.RemoveFilteredNamedPolicy("p", oldIndex, resource)
			if err != nil {
				panic(err)
			}
		}
	}

	if len(resourcesAdded) > 0 {
		permissionMock := &Permission{
			Owner:     permission.Owner,
			Name:      permission.Name,
			Users:     permission.Users,
			Roles:     permission.Roles,
			Domains:   permission.Domains,
			Resources: resourcesAdded,
			Actions:   permission.Actions,
			AbacRule:  permission.AbacRule,
		}
		operatePoliciesByPermission(permissionMock, newEnforcer, true, false)
		operatePoliciesByPermission(permissionMock, newEnforcer, true, true)

	}

	if len(actionsDeleted) > 0 {
		for _, resource := range oldPermission.Resources {
			for _, action := range actionsDeleted {
				_, err := oldEnforcer.RemoveFilteredNamedPolicy("p", oldIndex, resource, action)
				if err != nil {
					return false, err
				}
			}
		}
	}

	if len(actionsAdded) > 0 {

		permissionMock := &Permission{
			Owner:     permission.Owner,
			Name:      permission.Name,
			Users:     permission.Users,
			Roles:     permission.Roles,
			Domains:   permission.Domains,
			Resources: permission.Resources,
			Actions:   actionsAdded,
			AbacRule:  permission.AbacRule,
		}
		operatePoliciesByPermission(permissionMock, newEnforcer, true, false)
		operatePoliciesByPermission(permissionMock, newEnforcer, true, true)
	}

	affected, err := adapter.Engine.ID(core.PK{owner, name}).AllCols().Update(permission)
	if err != nil {
		panic(err)
	}

	return affected != 0, nil

}

func AddPermission(permission *Permission) (bool, error) {
	err := checkPermissionAbacRule(permission)
	if err != nil {
		return false, err
	}
	affected, err := adapter.Engine.Insert(permission)
	if err != nil {
		return false, err
	}

	if affected != 0 {
		addGroupingPolicies(permission)
		addPolicies(permission)
	}

	return affected != 0, nil
}

func AddPermissions(permissions []*Permission) bool {
	if len(permissions) == 0 {
		return false
	}

	affected, err := adapter.Engine.Insert(permissions)
	if err != nil {
		if !strings.Contains(err.Error(), "Duplicate entry") {
			panic(err)
		}
	}

	for _, permission := range permissions {
		// add using for loop
		if affected != 0 {
			addGroupingPolicies(permission)
			addPolicies(permission)
		}
	}
	return affected != 0
}

func AddPermissionsInBatch(permissions []*Permission) bool {
	batchSize := conf.GetConfigBatchSize()

	if len(permissions) == 0 {
		return false
	}

	affected := false
	for i := 0; i < (len(permissions)-1)/batchSize+1; i++ {
		start := i * batchSize
		end := (i + 1) * batchSize
		if end > len(permissions) {
			end = len(permissions)
		}

		tmp := permissions[start:end]
		// TODO: save to log instead of standard output
		// fmt.Printf("Add Permissions: [%d - %d].\n", start, end)
		if AddPermissions(tmp) {
			affected = true
		}
	}

	return affected
}

func DeletePermission(permission *Permission) (bool, error) {

	enforcer := getEnforcer(permission)
	index := 1
	if len(permission.Domains) > 0 {
		index = 2
	}

	permissions := GetPermissionsByAdapterAndDomainsAndRole(permission.Adapter, permission.Domains, "")
	judgeRepeatRole(enforcer, permission.Roles, permission.Domains, index, permissions)
	//removeGroupingPolicies(permission)
	removePolicies(permission)
	if permission.Adapter != "" && permission.Adapter != "permission_rule" {
		isEmpty, _ := adapter.Engine.IsTableEmpty(permission.Adapter)
		if isEmpty {
			err := adapter.Engine.DropTables(permission.Adapter)
			if err != nil {
				panic(err)
			}
		}
	}

	affected, err := adapter.Engine.ID(core.PK{permission.Owner, permission.Name}).Delete(&Permission{})
	if err != nil {
		panic(err)
	}

	return affected != 0, nil
}

func GetPermissionsByUser(userId string) []*Permission {
	permissions := []*Permission{}
	err := adapter.Engine.Where("users like ?", "%"+userId+"%").Find(&permissions)
	if err != nil {
		panic(err)
	}

	return permissions
}

func GetPermissionsAndRolesByUser(userId string) ([]*Permission, []*Role, error) {
	permissions := []*Permission{}
	err := adapter.Engine.Where("users like ?", "%"+userId+"\"%").Find(&permissions)
	if err != nil {
		return nil, nil, err
	}

	existedPerms := map[string]struct{}{}

	for _, perm := range permissions {
		perm.Users = nil

		if _, ok := existedPerms[perm.Name]; !ok {
			existedPerms[perm.Name] = struct{}{}
		}
	}

	permFromRoles := []*Permission{}

	roles, err := GetRolesByUser(userId)
	if err != nil {
		return nil, nil, err
	}

	for _, role := range roles {
		perms := []*Permission{}
		err := adapter.Engine.Where("roles like ?", "%"+role.Name+"\"%").Find(&perms)
		if err != nil {
			return nil, nil, err
		}
		permFromRoles = append(permFromRoles, perms...)
	}

	for _, perm := range permFromRoles {
		perm.Users = nil
		if _, ok := existedPerms[perm.Name]; !ok {
			existedPerms[perm.Name] = struct{}{}
			permissions = append(permissions, perm)
		}
	}

	return permissions, roles, nil
}

func GetPermissionsByRole(roleId string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := adapter.Engine.Where("roles like ?", "%"+roleId+"\"%").Find(&permissions)
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func GetPermissionsByAdapterAndDomainsAndRole(table string, domains []string, role string) []*Permission {
	permissions := []*Permission{}
	where := "adapter = " + "'" + table + "'"

	if l := len(domains); l > 0 {
		domainsWhere := make([]string, l)
		for k, v := range domains {
			domainsWhere[k] = "domains like " + "'%" + v + "%'"
		}
		orWhere := "(" + strings.Join(domainsWhere, " or ") + ")"
		where += " and " + orWhere
	} else {
		orWhere := "domains = '[]'"
		where += " and " + orWhere
	}

	if role != "" {
		orWhere := " roles like " + "'%" + role + "%'"
		where += " and " + orWhere
	}

	fmt.Println(where, "++++++++where++++++++")

	err := adapter.Engine.Where(where).Find(&permissions)
	if err != nil {
		panic(err)
	}
	return permissions
}

func GetPermissionsByResource(resourceId string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := adapter.Engine.Where("resources like ?", "%"+resourceId+"\"%").Find(&permissions)
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func GetPermissionsBySubmitter(owner string, submitter string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := adapter.Engine.Desc("created_time").Find(&permissions, &Permission{Owner: owner, Submitter: submitter})
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func GetPermissionsByModel(owner string, model string) ([]*Permission, error) {
	permissions := []*Permission{}
	err := adapter.Engine.Desc("created_time").Find(&permissions, &Permission{Owner: owner, Model: model})
	if err != nil {
		return permissions, err
	}

	return permissions, nil
}

func ContainsAsterisk(userId string, users []string) bool {
	containsAsterisk := false
	group, _ := util.GetOwnerAndNameFromId(userId)
	for _, user := range users {
		permissionGroup, permissionUserName := util.GetOwnerAndNameFromId(user)
		if permissionGroup == group && permissionUserName == "*" {
			containsAsterisk = true
			break
		}
	}

	return containsAsterisk
}

func RemoveGroupingPolicyByDomains(enforcer *casbin.Enforcer, domains []string, index int, roleName string) {
	if len(domains) > 0 {
		for _, domain := range domains {
			_, err := enforcer.RemoveFilteredGroupingPolicy(index-1, domain, roleName)
			if err != nil {
				panic(err)
			}
		}
	} else {
		_, err := enforcer.RemoveFilteredGroupingPolicy(index, roleName)
		if err != nil {
			panic(err)
		}
	}
}

func judgeRepeatRole(enforcer *casbin.Enforcer, roles []string, domains []string, index int, permissions []*Permission) {
	for _, role := range roles {
		var num int
		for _, p := range permissions {
			if ok, _ := util.InArray(role, p.Roles); ok {
				num++
				if num > 1 {
					break
				}
			}
		}
		if num <= 1 {
			RemoveGroupingPolicyByDomains(enforcer, domains, index, role)
		}
	}
}

func operateGroupingPoliciesByPermission(permission *Permission, enforcer *casbin.Enforcer, isAdd bool) {
	var err error
	domainExist := len(permission.Domains) > 0
	//permissionId := permission.Owner + "/" + permission.Name
	for _, role := range permission.Roles {
		roleObj, _ := GetRole(role)
		for _, user := range roleObj.Users {
			if domainExist {
				for _, domain := range permission.Domains {
					if isAdd {
						_, err = enforcer.AddNamedGroupingPolicy("g", user, domain, roleObj.Owner+"/"+roleObj.Name)
					} else {
						_, err = enforcer.RemoveNamedGroupingPolicy("g", user, domain, roleObj.Owner+"/"+roleObj.Name)
					}
					if err != nil {
						panic(err)
					}
				}
			} else {
				if isAdd {
					_, err = enforcer.AddNamedGroupingPolicy("g", user, roleObj.Owner+"/"+roleObj.Name)
				} else {
					_, err = enforcer.RemoveNamedGroupingPolicy("g", user, roleObj.Owner+"/"+roleObj.Name)
				}
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

func operatePoliciesByPermission(permission *Permission, enforcer *casbin.Enforcer, isAdd bool, isUser bool) {
	var err error
	//permissionId := permission.Owner + "/" + permission.Name
	column := permission.Roles
	if isUser {
		column = permission.Users
	}
	domainExist := len(permission.Domains) > 0
	for _, v := range column {
		for _, resource := range permission.Resources {
			for _, action := range permission.Actions {
				if domainExist {
					for _, domain := range permission.Domains {
						//if isAdd {
						//	_, err = enforcer.AddNamedPolicy("p", v, domain, resource, strings.ToLower(action), permission.AbacRule)
						//} else {
						//	_, err = enforcer.RemoveNamedPolicy("p", v, domain, resource, strings.ToLower(action), permission.AbacRule)
						//}
						//if err != nil {
						//	panic(err)
						//}

						policy := []interface{}{v, domain, resource, strings.ToLower(action)}
						if permission.AbacRule != "" {
							policy = append(policy, permission.AbacRule)
						}
						if isAdd {
							_, err = enforcer.AddNamedPolicy("p", policy...)
						} else {
							_, err = enforcer.RemoveNamedPolicy("p", policy...)
						}
						if err != nil {
							panic(err)
						}

					}
				} else {
					//if isAdd {
					//	_, err = enforcer.AddNamedPolicy("p", v, resource, strings.ToLower(action), permission.AbacRule)
					//} else {
					//	_, err = enforcer.RemoveNamedPolicy("p", v, resource, strings.ToLower(action), permission.AbacRule)
					//}
					//if err != nil {
					//	panic(err)
					//}

					policy := []interface{}{v, resource, strings.ToLower(action)}
					if permission.AbacRule != "" {
						policy = append(policy, permission.AbacRule)
					}
					if isAdd {
						_, err = enforcer.AddNamedPolicy("p", policy...)
					} else {
						_, err = enforcer.RemoveNamedPolicy("p", policy...)
					}
					if err != nil {
						panic(err)
					}
				}
			}
		}
	}
}

func GetMaskedPermissions(permissions []*Permission) []*Permission {
	for _, permission := range permissions {
		permission.Users = nil
		permission.Submitter = ""
	}

	return permissions

}

// GroupPermissionsByModelAdapter group permissions by model and adapter.
// Every model and adapter will be a key, and the value is a list of permission ids.
// With each list of permission ids have the same key, we just need to init the
// enforcer and do the enforce/batch-enforce once (with list of permission ids
// as the policyFilter when the enforcer load policy).
func GroupPermissionsByModelAdapter(permissions []*Permission) map[string][]string {
	m := make(map[string][]string)

	for _, permission := range permissions {
		key := permission.Model + permission.Adapter
		permissionIds, ok := m[key]
		if !ok {
			m[key] = []string{permission.GetId()}
		} else {
			m[key] = append(permissionIds, permission.GetId())
		}
	}

	return m
}

func checkPermissionAbacRule(permission *Permission) error {
	if permission.AbacRule != "" {

		permissionModel, err := getModel(permission.Owner, permission.Model)
		if err != nil {
			panic(err)
		}

		if !strings.Contains(permissionModel.ModelText, "sub_rule") {
			return errors.New("Must include specific fields")
		}

		match, _ := regexp.MatchString(`"`, permission.AbacRule)
		if match {
			//error.Error("Cannot contain double quotation marks")
			return errors.New("Cannot contain double quotation marks")
		}

	}

	return nil
}
