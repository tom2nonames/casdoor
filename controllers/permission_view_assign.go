package controllers

import (
	"encoding/json"
	"github.com/casdoor/casdoor/object"
)

// AddPermissionViewAssign
// @Title AddPermissionViewAssign
// @Tag PermissionViewAssign API
// @Description add permission_view_assign
// @Param   body    body   object.PermissionViewAssign  true        "The details of the permissionViewAssign"
// @Success 200 {object} controllers.Response The Response object
// @router /add-permission-view-Assign [post]
func (c *ApiController) AddPermissionViewAssign() {
	var permissionViewAssign object.PermissionViewAssign
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &permissionViewAssign)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddPermissionViewAssign(&permissionViewAssign))
	c.ServeJSON()
}
