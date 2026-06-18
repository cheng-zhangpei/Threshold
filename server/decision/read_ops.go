package decision

// READ_OPS 只读操作集合
// Router 判定 L0（直接穿透）的操作类型
// TODO(cheng) 这里的定位有点尴尬，到后面有需求做一下透传看看
var READ_OPS = map[string]bool{
	"GET /api/cloud/public/images":           true,
	"GET /api/cloud/public/images/download":  true,
	"GET /api/cloud/private/images":          true,
	"GET /api/cloud/private/images/download": true,
	"GET /api/local/images":                  true,
	"GET /api/local/images/download":         true,
	"GET /api/local/stats":                   true,
	"GET /api/vms/status":                    true,
	"GET /api/vms/running":                   true,
	"GET /api/vms/log":                       true,
	"GET /api/security/policy":               true,
	"GET /api/audit/events":                  true,
}
