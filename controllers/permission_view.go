package controllers

import (
	"encoding/json"
	"github.com/casdoor/casdoor/object"
)

type PermissionViewEnforceForm struct {
	Code    string `json:"code"`
	Subject string `json:"subject"`
	SubRule string `json:"sub_rule"`
}

// AddPermissionView
// @Title AddPermissionView
// @Tag PermissionView API
// @Description add permissionView
// @Param   body    body   object.PermissionView  true        "The details of the permissionView"
// @Success 200 {object} controllers.Response The Response object
// @router /add-permission-view [post]
func (c *ApiController) AddPermissionView() {
	var permissionView object.PermissionView
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &permissionView)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if permissionView.Model != "model_group_abac" {
		c.ResponseError("model must be model_group_abac")
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddPermissionView(&permissionView))
	c.ServeJSON()
}

func (c *ApiController) PermissionViewGenerateJsonTree() {
	jsonStr := c.Ctx.Request.Form.Get("jsonStr")
	//fmt.Println(jsonStr)
	resources, err := object.PermissionViewGenerateJsonTree(jsonStr)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.Data["json"] = resources
	c.ServeJSON()
}

func (c *ApiController) PermissionViewEnforce() {
	var params PermissionViewEnforceForm
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &params)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	resources, err := object.PermissionViewEnforce(params.Code, params.Subject, params.SubRule)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.Data["json"] = resources
	c.ServeJSON()
}
