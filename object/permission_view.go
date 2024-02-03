package object

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type PermissionView struct {
	Owner       string                     `json:"owner"`
	DisplayName string                     `json:"display_name"`
	Code        string                     `json:"code"`
	Resources   []*PermissionViewResources `json:"resources"`
	Adapter     string                     `json:"adapter"`
	Model       string                     `json:"model"`
	IsAbac      bool                       `json:"is_abac"`
	IsEnabled   bool                       `json:"is_enabled"`
}

type PermissionViewResources struct {
	Name      string                     `json:"name"`
	Type      string                     `json:"type"`
	AbacRule  string                     `json:"abac_rule"`
	Condition string                     `json:"condition"`
	Result    bool                       `json:"result"`
	Children  []*PermissionViewResources `json:"children"`
}

func AddPermissionView(permissionView *PermissionView) (bool, error) {
	affected, err := adapter.Engine.Insert(permissionView)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func GetPermissionViewByCode(owner string, code string) (*PermissionView, error) {
	//permissionView := &PermissionView{}
	//err := adapter.Engine.Find(permissionView, &PermissionView{Owner: owner, Code: code})
	permissionView := &PermissionView{Owner: owner, Code: code}
	_, err := adapter.Engine.Get(permissionView)
	if err != nil {
		return permissionView, err
	}

	return permissionView, nil
}

func PermissionViewGenerateJsonTree(jsonStr string) ([]*PermissionViewResources, error) {
	m := make(map[string]interface{})
	err := json.Unmarshal([]byte(jsonStr), &m)
	if err != nil {
		return nil, err
	}

	resources := make([]*PermissionViewResources, 0, 10)

	for k, v := range m {
		resource := &PermissionViewResources{Name: k, Children: make([]*PermissionViewResources, 0, 0)}
		generateJsonTree(v, resource)
		resources = append(resources, resource)
	}

	return resources, nil
}

func generateJsonTree(value interface{}, preResource *PermissionViewResources) {
	//resource := &PermissionViewResources{}
	valueOf := reflect.ValueOf(value)
	switch valueOf.Kind() {
	case reflect.Slice:
		preResource.Type = generateResourceType(preResource.Type, "array")
		s := value.([]interface{})
		if len(s) == 0 {
			return
		}
		generateJsonTree(s[0], preResource)
	case reflect.Map:
		preResource.Type = generateResourceType(preResource.Type, "object")
		m := value.(map[string]interface{})
		for k, v := range m {
			resource := &PermissionViewResources{Name: k, Children: make([]*PermissionViewResources, 0, 0)}
			preResource.Children = append(preResource.Children, resource)
			generateJsonTree(v, resource)
		}
	default:
		preResource.Type = generateResourceType(preResource.Type, "single")
		return
	}
}

func generateResourceType(preType string, curType string) string {
	if preType == "" {
		return curType
	}

	if curType == "single" {
		types := strings.Split(preType, ".")
		if lastType := types[len(types)-1]; lastType == "array" {
			return preType
		}
	}

	return fmt.Sprintf("%s.%s", preType, curType)
}

func PermissionViewEnforce(code string, subject string, subRule string) ([]*PermissionViewResources, error) {
	//subRule = `{"Name": "alice", "Age": 16}`
	permissionView := &PermissionView{Code: code}
	existed, err := adapter.Engine.Get(permissionView)
	if !existed {
		return nil, fmt.Errorf("PermissionView not found")
	}

	if err != nil {
		return nil, err
	}

	subRuleMap := make(map[string]interface{}, 5)
	err = json.Unmarshal([]byte(subRule), &subRuleMap)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//permissionViewResources := []*PermissionViewResources{}
	permissionViewResources := permissionView.Resources
	permissionViewResourcesMap := make(map[string]map[string]string, 5)
	resourcesMap := make([][]interface{}, 0, 5)
	generateResourcesMap(permissionView.Code, permissionViewResources, permissionViewResourcesMap)
	for resourceName, _ := range permissionViewResourcesMap {
		resourcesMap = append(resourcesMap, []interface{}{subject, subRule, resourceName, "read"})
		//resourcesMap = append(resourcesMap, []interface{}{subject, subRuleMap, resourceName, "read"})
	}

	permission := &Permission{
		Adapter: permissionView.Adapter,
		Model:   permissionView.Model,
		Owner:   permissionView.Owner,
	}

	enforcer := getEnforcer(permission)
	enforcer.EnableAcceptJsonRequest(true)
	allows, err := enforcer.BatchEnforce(resourcesMap)
	if err != nil {
		return nil, err
	}
	resourcesResultMap := make(map[string]bool, 5)
	for index, allow := range allows {
		resourceName := resourcesMap[index][2].(string)
		resourcesResultMap[resourceName] = allow
	}

	fillresourcesResult(permissionView.Code, permissionViewResources, resourcesResultMap)
	return permissionViewResources, nil
}

func fillresourcesResult(prefix string, resources []*PermissionViewResources, resourcesResultMap map[string]bool) {
	for _, resource := range resources {
		keyName := fmt.Sprintf("%s.%s", prefix, resource.Name)
		resource.Result = resourcesResultMap[keyName]
		if len(resource.Children) > 0 {
			mark := ""
			if count := strings.Count(resource.Type, "array"); count > 0 {
				mark = strings.Repeat("[]", count)
			}
			keyName = keyName + mark
			fillresourcesResult(keyName, resource.Children, resourcesResultMap)
		}
	}
}
