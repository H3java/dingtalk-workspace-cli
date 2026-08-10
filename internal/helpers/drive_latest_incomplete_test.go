package helpers

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// 本文件锁定 drive list --latest 的两个 P1 行为，独立于 pr868_*_test.go / drive_depth_test.go：
//   P1-a：sortTime 是内部排序字段，任何输出路径都不得泄露进契约；
//   P1-b：递归途中目录读取失败时，Top-N 建立在不完整集合上，必须拒绝产出而非吐 partial。
// 改代码前这些断言对 origin/main 应为红：main 采集端无条件写 sortTime、emit 仅在单层 latest 才剥；
// main 尾部拒绝 guard 只拦截断、不拦目录失败。
//
// 另锁定 review 反馈的两个边界：
//   截断与目录失败同真时，失败详情（permission_denied 等）不得被截断提示吞掉；
//   拒绝产出时给的恢复命令必须保留原查询域（--workspace / --space-id），照抄不会切换查询域。

// depthItemsWithSortTime 断言 stdout 每个 item 都不含内部排序字段 sortTime。
func assertNoSortTime(t *testing.T, result map[string]any) {
	t.Helper()
	items, ok := result["items"].([]any)
	if !ok {
		t.Fatalf("items missing or wrong type: %#v", result["items"])
	}
	for i, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("item[%d] not an object: %#v", i, raw)
		}
		if _, leaked := item["sortTime"]; leaked {
			t.Fatalf("item[%d] leaked internal sortTime into output contract: %#v", i, item)
		}
	}
}

// TestDriveLatestNoSortTimeLeak 覆盖 main 的覆盖漏洞：main 的
// TestCrossPlatformCoverageDriveDepthLatestTruncatedAndSortTime 名字带 SortTime，
// 却只断言 TRUNCATED、从不检查输出无 sortTime（`_ = out`）。这里把两条泄露路径都钉住。
func TestDriveLatestNoSortTimeLeak(t *testing.T) {
	// 场景 A：depth>1 --latest —— 走 applyDriveListLatest（只读 sortTime、不剥），reqDepth>1 不触发 strip。
	t.Run("depth_latest", func(t *testing.T) {
		useDriveDepthArgs(t)
		caller := &scriptedToolCaller{steps: []scriptedToolStep{
			{text: `{"items":[{"fileId":"f1","name":"a.txt","type":"FILE","modifiedTime":1000},{"fileId":"f2","name":"b.txt","type":"FILE","modifiedTime":2000}]}`},
		}}
		out := installDepthCaller(t, caller)
		cmd := &cobra.Command{Use: "list"}
		if err := runDriveListDepth(cmd, newDrivePanDepthRoute(), map[string]any{}, "", 3, "", true, 5); err != nil {
			t.Fatalf("runDriveListDepth: %v", err)
		}
		assertNoSortTime(t, decodeDepthResult(t, out))
	})

	// 场景 B：--depth 2 无 latest —— 走 else 分支树序排序，同样不触发 strip。
	t.Run("depth_no_latest", func(t *testing.T) {
		useDriveDepthArgs(t)
		caller := &scriptedToolCaller{steps: []scriptedToolStep{
			{text: `{"items":[{"fileId":"f1","name":"a.txt","type":"FILE","modifiedTime":1000},{"fileId":"f2","name":"c.txt","type":"FILE","modifiedTime":3000}]}`},
		}}
		out := installDepthCaller(t, caller)
		cmd := &cobra.Command{Use: "list"}
		if err := runDriveListDepth(cmd, newDrivePanDepthRoute(), map[string]any{}, "", 2, "", true, 0); err != nil {
			t.Fatalf("runDriveListDepth: %v", err)
		}
		assertNoSortTime(t, decodeDepthResult(t, out))
	})
}

// TestDriveLatestRefusesOnFolderFailure 覆盖 P1-b：递归途中一个可恢复目录失败（403/business，
// 非 auth 非限流 → 记 errs[] 跳过），Top-N 落在不完整集合上，必须拒绝产出。
// 构造：根目录成功产出 FOLDER+FILE（collected>0 且 dirA 入队），子目录返回 forbidden.* →
// recoverable → errs=[1]。旧代码尾部 `if truncated && latest>0` 不触发 → emit 吐 partial（err=nil）；
// 新代码 `len(errs)>0` → LATEST_SCAN_INCOMPLETE 且 stdout 无 items。
func TestDriveLatestRefusesOnFolderFailure(t *testing.T) {
	useDriveDepthArgs(t)
	caller := &scriptedToolCaller{steps: []scriptedToolStep{
		{text: `{"items":[{"fileId":"dirA","name":"dirA","type":"FOLDER"},{"fileId":"fX","name":"x.txt","type":"FILE","modifiedTime":1000}]}`},
		{text: `{"errorCode":"forbidden.noPermission","errorMsg":"denied"}`},
	}}
	out := installDepthCaller(t, caller)
	cmd := &cobra.Command{Use: "list"}
	err := runDriveListDepth(cmd, newDrivePanDepthRoute(), map[string]any{}, "", 3, "", true, 5)
	if err == nil || !strings.Contains(err.Error(), "LATEST_SCAN_INCOMPLETE") {
		t.Fatalf("err = %v, want LATEST_SCAN_INCOMPLETE", err)
	}
	// 拒绝产出：stdout 必须没有 items（不是 partial）。旧代码此处会吐 partial，断言随之失败。
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on refusal, got: %s", out.String())
	}
}

// TestDriveLatestRefusesOnTruncationWithFolderFailure 端到端证明「截断 + 目录失败」组合确实可达：
// 根目录出 dirA/dirB 两个子目录 → dirA 权限失败记 errs[] → dirB 返回 2000 条触发全局截断，
// 尾部 guard 拿到 truncated=true 且 len(errs)=1。旧实现在此让 truncated 短路，permission_denied
// 详情整块丢失（review 反馈的阻塞点）；现在两个 token 与失败详情都必须在。
func TestDriveLatestRefusesOnTruncationWithFolderFailure(t *testing.T) {
	useDriveDepthArgs(t)
	var bulk strings.Builder
	bulk.WriteString(`{"items":[`)
	for i := 0; i < driveDepthMaxItems; i++ {
		if i > 0 {
			bulk.WriteString(",")
		}
		fmt.Fprintf(&bulk, `{"fileId":"f%d","name":"file-%d.txt","type":"FILE","modifiedTime":%d}`, i, i, 1000+i)
	}
	bulk.WriteString(`]}`)
	caller := &scriptedToolCaller{steps: []scriptedToolStep{
		{text: `{"items":[{"fileId":"dirA","name":"报表","type":"FOLDER"},{"fileId":"dirB","name":"dirB","type":"FOLDER"}]}`},
		{text: `{"errorCode":"forbidden.noPermission","errorMsg":"denied"}`}, // dirA：可恢复 → 记 errs[]
		{text: bulk.String()}, // dirB：撞 2000 上限 → truncated
	}}
	out := installDepthCaller(t, caller)
	cmd := &cobra.Command{Use: "list"}
	err := runDriveListDepth(cmd, newDrivePanDepthRoute(), map[string]any{}, "", 3, "", true, 5)
	var cliErr *CLIError
	if !errors.As(err, &cliErr) || cliErr.Code != CodeContentTruncated {
		t.Fatalf("err = %T %v, want CodeContentTruncated", err, err)
	}
	msg := cliErr.Message
	if !strings.Contains(msg, "LATEST_SCAN_TRUNCATED") {
		t.Fatalf("组合场景缺 TRUNCATED token: %q", msg)
	}
	// 旧实现在这里丢掉整段目录失败详情。
	if !strings.Contains(msg, "LATEST_SCAN_INCOMPLETE") ||
		!strings.Contains(msg, "folder=报表") ||
		!strings.Contains(msg, "permission_denied") {
		t.Fatalf("组合场景丢失目录失败详情: %q", msg)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on refusal, got: %s", out.String())
	}
}

// TestDriveLatestScopeWiredFromCommand 端到端验证查询域从原命令一路带到恢复命令：单测构造器
// 拿不到的是 runDriveListDepth 里的接线（driveLatestScopeFromCmd(cmd, maxDepth)），这里补上。
func TestDriveLatestScopeWiredFromCommand(t *testing.T) {
	useDriveDepthArgs(t)
	caller := &scriptedToolCaller{steps: []scriptedToolStep{
		{text: `{"items":[{"fileId":"dirA","name":"dirA","type":"FOLDER"},{"fileId":"fX","name":"x.txt","type":"FILE","modifiedTime":1000}]}`},
		{text: `{"errorCode":"forbidden.noPermission","errorMsg":"denied"}`},
	}}
	installDepthCaller(t, caller)
	cmd := newDriveListScopeCmd(t, map[string]string{"space-id": "sp-7"})
	err := runDriveListDepth(cmd, newDrivePanDepthRoute(), map[string]any{"spaceId": "sp-7"}, "", 4, "", true, 5)
	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("err = %T %v", err, err)
	}
	// 恢复命令必须带原 --space-id，且给出原 --depth 层数。
	assertDriveLatestSuggestion(t, cliErr.Suggestion, "--space-id sp-7")
	if !strings.Contains(cliErr.Suggestion, "--depth 4") {
		t.Fatalf("恢复命令应保留原层数: %q", cliErr.Suggestion)
	}
}

// TestDriveLatestRefusesOnUnrecoverableFailure 覆盖 P1-b 的另一半：递归途中遇不可恢复错误
// （auth 过期 / 网络不可达）且 latest>0 时，不吐 partial，直接回根因错误。
// 与 latest=0 的既有行为（TestCrossPlatformCoverageRunDriveListDepthUnrecoverable：partial
// + errors[] 进 stdout 后非零退出）对照——latest 下 partial 的 Top-N 会被误读为全局最新，
// 故必须拒绝产出；回根因错误而非 INCOMPLETE token，因为 auth/网络比通用截断提示更可操作。
func TestDriveLatestRefusesOnUnrecoverableFailure(t *testing.T) {
	useDriveDepthArgs(t)
	caller := &scriptedToolCaller{steps: []scriptedToolStep{
		{text: `{"items":[{"fileId":"dirA","name":"dirA","type":"FOLDER"},{"fileId":"fX","name":"x.txt","type":"FILE","modifiedTime":1000}]}`},
		{text: `{"errorCode":"DWS_SERVICE_UNAUTHORIZED"}`},
	}}
	out := installDepthCaller(t, caller)
	cmd := &cobra.Command{Use: "list"}
	err := runDriveListDepth(cmd, newDrivePanDepthRoute(), map[string]any{}, "", 3, "", true, 5)
	// 回根因错误：Code 仍是 auth 过期，不被包装成 LATEST_SCAN_INCOMPLETE。
	var cliErr *CLIError
	if !errors.As(err, &cliErr) || cliErr.Code != CodeAuthTokenExpired {
		t.Fatalf("err = %T %v, want CodeAuthTokenExpired", err, err)
	}
	if strings.Contains(cliErr.Message, "LATEST_SCAN_INCOMPLETE") {
		t.Fatalf("unrecoverable 应回根因错误而非 INCOMPLETE 包装: %q", cliErr.Message)
	}
	// 拒绝产出：不吐 partial（对照 latest=0 时会输出 2 条 items + 1 条 errors）。
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on refusal, got: %s", out.String())
	}
}

// TestDriveLatestIncompleteErrorBranches 直接单测构造器的各条分支。
func TestDriveLatestIncompleteErrorBranches(t *testing.T) {
	// 纯截断分支：errs 为空 → 只有 TRUNCATED。
	t.Run("truncated_only", func(t *testing.T) {
		err := driveLatestIncompleteError(5, true, nil, driveLatestScope{depth: 3})
		var cliErr *CLIError
		if !errors.As(err, &cliErr) || cliErr.Code != CodeContentTruncated {
			t.Fatalf("err = %T %v, want CodeContentTruncated", err, err)
		}
		if !strings.Contains(cliErr.Message, "LATEST_SCAN_TRUNCATED") {
			t.Fatalf("message = %q", cliErr.Message)
		}
		if strings.Contains(cliErr.Message, "LATEST_SCAN_INCOMPLETE") {
			t.Fatalf("无目录失败时不应出现 INCOMPLETE: %q", cliErr.Message)
		}
		assertDriveLatestSuggestion(t, cliErr.Suggestion, "")
	})

	// 纯目录失败分支：未截断 → 只有 INCOMPLETE，Message 含首个失败的 folder/depth/reason。
	t.Run("folder_failure_only", func(t *testing.T) {
		err := driveLatestIncompleteError(3, false, twoDriveDepthErrors(), driveLatestScope{depth: 3})
		var cliErr *CLIError
		if !errors.As(err, &cliErr) || cliErr.Code != CodeContentTruncated {
			t.Fatalf("err = %T %v, want CodeContentTruncated", err, err)
		}
		msg := cliErr.Message
		if !strings.Contains(msg, "LATEST_SCAN_INCOMPLETE") ||
			!strings.Contains(msg, "报表") ||
			!strings.Contains(msg, "depth=2") ||
			!strings.Contains(msg, "permission_denied") ||
			!strings.Contains(msg, "2 个目录未读全") {
			t.Fatalf("message = %q", msg)
		}
		if strings.Contains(msg, "LATEST_SCAN_TRUNCATED") {
			t.Fatalf("未截断时不应出现 TRUNCATED: %q", msg)
		}
		assertDriveLatestSuggestion(t, cliErr.Suggestion, "")
	})

	// 组合分支（review 反馈的阻塞点）：截断与目录失败同真时，旧实现让 truncated 短路、
	// permission_denied 这类目录失败详情整块丢失。现在两个 token 都必须在，且失败详情不得被吞。
	t.Run("truncated_with_folder_failures", func(t *testing.T) {
		err := driveLatestIncompleteError(4, true, twoDriveDepthErrors(), driveLatestScope{depth: 3})
		var cliErr *CLIError
		if !errors.As(err, &cliErr) || cliErr.Code != CodeContentTruncated {
			t.Fatalf("err = %T %v, want CodeContentTruncated", err, err)
		}
		msg := cliErr.Message
		// 两个成因都要可被消费方 token 匹配到。
		if !strings.Contains(msg, "LATEST_SCAN_INCOMPLETE") || !strings.Contains(msg, "LATEST_SCAN_TRUNCATED") {
			t.Fatalf("组合场景需同时带两个 token: %q", msg)
		}
		// 目录失败详情必须完整保留——这是用户唯一能动手修的线索。
		if !strings.Contains(msg, "报表") ||
			!strings.Contains(msg, "depth=2") ||
			!strings.Contains(msg, "permission_denied") ||
			!strings.Contains(msg, "2 个目录未读全") {
			t.Fatalf("组合场景丢失目录失败详情: %q", msg)
		}
		if !strings.Contains(msg, "拒绝输出不完整的 Top-4") {
			t.Fatalf("message 缺少拒绝产出结论: %q", msg)
		}
		assertDriveLatestSuggestion(t, cliErr.Suggestion, "")
		// 组合场景的指引要同时覆盖两条补救：换可读目录 + 降层数。
		if !strings.Contains(cliErr.Suggestion, "确认目录权限") || !strings.Contains(cliErr.Suggestion, "--depth") {
			t.Fatalf("组合场景 suggestion 需同时给出权限与降层数补救: %q", cliErr.Suggestion)
		}
	})

	// folderName 为空回落 folderID；folderID 也空回落 <root>。
	t.Run("folder_fallback", func(t *testing.T) {
		byID := driveLatestIncompleteError(1, false, []driveDepthError{{FolderID: "fid-x"}}, driveLatestScope{depth: 2})
		if !strings.Contains(byID.Error(), "folder=fid-x") {
			t.Fatalf("fallback to folderID: %v", byID)
		}
		byRoot := driveLatestIncompleteError(1, false, []driveDepthError{{}}, driveLatestScope{depth: 2})
		if !strings.Contains(byRoot.Error(), "folder=<root>") {
			t.Fatalf("fallback to <root>: %v", byRoot)
		}
	})
}

// twoDriveDepthErrors 是两条目录失败样本，首条用于断言「首个失败」详情。
func twoDriveDepthErrors() []driveDepthError {
	return []driveDepthError{
		{Depth: 2, FolderID: "fid-9", FolderName: "报表", Reason: "permission_denied", Message: "denied"},
		{Depth: 1, FolderID: "fid-3", FolderName: "归档", Reason: "api_error", Message: "boom"},
	}
}

// TestDriveLatestScopePreservedInSuggestion 覆盖 review 反馈的第二个阻塞点：恢复命令此前固定
// 生成 `dws drive list --folder ...`，把原调用的 --workspace / --space-id 丢掉。用户照抄后
// 会从知识库切到普通钉盘（或从指定钉盘空间切到「我的文件」），在另一个查询域里拿到一份
// 「看起来对」的 Top-N —— 比直接报错更难发现。
func TestDriveLatestScopePreservedInSuggestion(t *testing.T) {
	cases := []struct {
		name  string
		flags map[string]string
		want  string
	}{
		// 知识库路由：--workspace 决定路由，丢了就切到普通钉盘。
		{name: "workspace", flags: map[string]string{"workspace": "ws-1"}, want: "--workspace ws-1"},
		// 别名路径：--workspace-id 与 --workspace 同源（flagOrFallback）。
		{name: "workspace_id_alias", flags: map[string]string{"workspace-id": "ws-alias"}, want: "--workspace ws-alias"},
		// 钉盘路由：--space-id 丢了就退回「我的文件」。
		{name: "space_id", flags: map[string]string{"space-id": "sp-7"}, want: "--space-id sp-7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := driveLatestScopeFromCmd(newDriveListScopeCmd(t, tc.flags), 3)
			// 三条成因组合下的恢复命令都必须带原查询域。
			for _, variant := range []struct {
				label     string
				truncated bool
				errs      []driveDepthError
			}{
				{"truncated_only", true, nil},
				{"folder_failure_only", false, twoDriveDepthErrors()},
				{"both", true, twoDriveDepthErrors()},
			} {
				err := driveLatestIncompleteError(5, variant.truncated, variant.errs, scope)
				var cliErr *CLIError
				if !errors.As(err, &cliErr) {
					t.Fatalf("%s: err = %T %v", variant.label, err, err)
				}
				assertDriveLatestSuggestion(t, cliErr.Suggestion, tc.want)
			}
		})
	}

	// --workspace 优先于 --space-id：与 drive list 的路由判定同序（先看 workspace 再看 space-id），
	// 否则恢复命令会把知识库查询写成钉盘查询。
	t.Run("workspace_wins_over_space_id", func(t *testing.T) {
		scope := driveLatestScopeFromCmd(newDriveListScopeCmd(t, map[string]string{
			"workspace": "ws-1", "space-id": "sp-7",
		}), 3)
		err := driveLatestIncompleteError(5, false, twoDriveDepthErrors(), scope)
		suggestion := err.(*CLIError).Suggestion
		if !strings.Contains(suggestion, "--workspace ws-1") || strings.Contains(suggestion, "--space-id") {
			t.Fatalf("workspace 应优先且不混入 space-id: %q", suggestion)
		}
	})

	// 无查询域时不得凭空造 flag（原调用就是「我的文件」根，硬塞 scope 同样是改查询域）。
	t.Run("no_scope_adds_nothing", func(t *testing.T) {
		scope := driveLatestScopeFromCmd(newDriveListScopeCmd(t, nil), 3)
		err := driveLatestIncompleteError(5, false, twoDriveDepthErrors(), scope)
		suggestion := err.(*CLIError).Suggestion
		if strings.Contains(suggestion, "--workspace") || strings.Contains(suggestion, "--space-id") {
			t.Fatalf("无 scope 时不应凭空造查询域 flag: %q", suggestion)
		}
		assertDriveLatestSuggestion(t, suggestion, "")
	})

	// depth==1（知识库 --latest 单层）时不给 --depth 1：partial+errors[] 契约只在多层成立，
	// 硬塞 --depth 1 会让「去掉 --latest 看明细」的子句自相矛盾。
	t.Run("single_depth_omits_depth_flag", func(t *testing.T) {
		err := driveLatestIncompleteError(5, false, twoDriveDepthErrors(), driveLatestScope{flags: "--workspace ws-1", depth: 1})
		suggestion := err.(*CLIError).Suggestion
		if strings.Contains(suggestion, "--depth") {
			t.Fatalf("单层不应出现 --depth: %q", suggestion)
		}
	})

	// 多层时给出确切层数，用户无需把 <原层数> 换成数字。
	t.Run("multi_depth_emits_actual_depth", func(t *testing.T) {
		err := driveLatestIncompleteError(5, false, twoDriveDepthErrors(), driveLatestScope{flags: "--space-id sp-7", depth: 4})
		suggestion := err.(*CLIError).Suggestion
		if !strings.Contains(suggestion, "--depth 4") {
			t.Fatalf("应给出原层数 --depth 4: %q", suggestion)
		}
		if strings.Contains(suggestion, "<原层数>") {
			t.Fatalf("不应残留占位符: %q", suggestion)
		}
	})
}

// newDriveListScopeCmd 造一个带 drive list 查询域 flag 的命令。flag 名与 newDriveCommand 里
// driveListCmd 的注册保持一致；workspace-id 是 cross-product 别名，此处显式注册以覆盖别名路径。
func newDriveListScopeCmd(t *testing.T, flags map[string]string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "list"}
	cmd.Flags().String("workspace", "", "")
	cmd.Flags().String("workspace-id", "", "")
	cmd.Flags().String("space-id", "", "")
	for name, value := range flags {
		if err := cmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set --%s=%s: %v", name, value, err)
		}
	}
	return cmd
}

// assertDriveLatestSuggestion 钉住 Suggestion 的三条约束：
//  1. 每条示例命令都带原查询域 wantScope（空串表示原调用无查询域，此时只跳过该项检查）；
//  2. 含 --latest 的引导子句存在；
//  3. 「去掉 --latest」子句给出的示例命令本身不带 --latest（否则照抄复现同一错误）。
func assertDriveLatestSuggestion(t *testing.T, suggestion, wantScope string) {
	t.Helper()
	clauses := strings.Split(suggestion, "；")
	sawLatestGuide := false
	for _, clause := range clauses {
		cmd := extractTrailingDwsCommand(clause)
		if cmd == "" {
			continue
		}
		if wantScope != "" && !strings.Contains(cmd, wantScope) {
			t.Fatalf("示例命令丢失原查询域 %q（照抄会切换查询域）: %q", wantScope, cmd)
		}
		if strings.Contains(clause, "去掉 --latest") {
			if strings.Contains(cmd, "--latest") {
				t.Fatalf("「去掉 --latest」子句的示例命令仍含 --latest: %q", cmd)
			}
			continue
		}
		if strings.Contains(cmd, "--latest") {
			sawLatestGuide = true
		}
	}
	if !sawLatestGuide {
		t.Fatalf("no --latest-bearing guidance clause in suggestion: %q", suggestion)
	}
}

// extractTrailingDwsCommand 抽子句里以 "dws " 开头的尾部命令片段（到子句末），无则空串。
func extractTrailingDwsCommand(clause string) string {
	idx := strings.LastIndex(clause, "dws ")
	if idx < 0 {
		return ""
	}
	return clause[idx:]
}
