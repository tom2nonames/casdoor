package object

import (
	"github.com/agiledragon/gomonkey/v2"
	"github.com/casbin/casbin/v2"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestBatchEnforce(t *testing.T) {

	rules := []PermissionRule{
		{Id: "id1", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //true
		{Id: "id2", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //true
		{Id: "id1", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //false
		{Id: "id3", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //true
		{Id: "id2", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //false
		{Id: "id2", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //false
		{Id: "id5", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //true
		{Id: "id4", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //false
		{Id: "id1", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //true
		{Id: "id4", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //true
		{Id: "id2", V0: "v0", V1: "v1", V2: "v2", V3: "v3"}, //false
	}

	want := []bool{true, true, false, true, false, false, true, false, true, true, false}

	getPermissionPatch := gomonkey.ApplyFunc(GetPermission, func(id string) *Permission {
		return &Permission{}
	})

	getEnforcerPatch := gomonkey.ApplyFunc(getEnforcer, func(permission *Permission) *casbin.Enforcer {
		return &casbin.Enforcer{}
	})

	e := &casbin.Enforcer{}
	batchEnforcePatch := gomonkey.ApplyMethodSeq(reflect.TypeOf(e), "BatchEnforce",
		[]gomonkey.OutputCell{
			{Values: gomonkey.Params{[]bool{true, false, true}, nil}},
			{Values: gomonkey.Params{[]bool{true, false, false, false}, nil}},
			{Values: gomonkey.Params{[]bool{true}, nil}},
			{Values: gomonkey.Params{[]bool{false, true}, nil}},
			{Values: gomonkey.Params{[]bool{true}, nil}},
		})

	defer func() {
		getPermissionPatch.Reset()
		getEnforcerPatch.Reset()
		batchEnforcePatch.Reset()
	}()

	got := BatchEnforce(rules)

	assert.Equal(t, want, got, "The returned value not is expected")

}
