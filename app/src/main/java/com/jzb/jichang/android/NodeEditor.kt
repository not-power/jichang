package com.jzb.jichang.android

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.jzb.jichang.android.model.ProxyNode
import com.jzb.jichang.android.service.MihomoNodeOptionsYaml
import com.jzb.jichang.android.service.NodeProtocolOptions

private const val OTHER = "其他协议"

@Composable
internal fun NodeEditorDialog(
    node: ProxyNode?, onDismiss: () -> Unit,
    onSave: (String, String, String, Int, Map<String, Any?>) -> Unit,
) {
    val key = node?.id ?: "new-node"
    val initialOptions = remember(key) { NodeProtocolOptions.canonicalOptions(node?.type.orEmpty(), node?.options.orEmpty()).filterKeys { it !in setOf("name", "type", "server", "port") } }
    val initialMode = remember(key) { node?.let { NodeProtocolOptions.mode(it.type, it.options) } ?: if (node == null) NodeProtocolOptions.REALITY else OTHER }
    var selected by rememberSaveable(key) { mutableStateOf(initialMode) }
    var name by rememberSaveable(key) { mutableStateOf(node?.name.orEmpty()) }
    var server by rememberSaveable(key) { mutableStateOf(node?.server.orEmpty()) }
    var port by rememberSaveable(key) { mutableStateOf(node?.port?.toString() ?: "443") }
    var otherType by rememberSaveable(key) { mutableStateOf(node?.type.orEmpty()) }
    val initialReality = remember(key) { if (node != null && initialMode == NodeProtocolOptions.REALITY) initialOptions else NodeProtocolOptions.defaults(NodeProtocolOptions.REALITY) }
    val initialHy2 = remember(key) { if (initialMode == NodeProtocolOptions.HY2) initialOptions else NodeProtocolOptions.defaults(NodeProtocolOptions.HY2) }
    val realityBaseline = remember(key) { MihomoNodeOptionsYaml.dump(initialReality) }
    val hy2Baseline = remember(key) { MihomoNodeOptionsYaml.dump(initialHy2) }
    val otherBaseline = remember(key) { MihomoNodeOptionsYaml.dump(initialOptions) }
    var reality by rememberSaveable(key, stateSaver = jsonSaver<Map<String, Any?>>()) { mutableStateOf(initialReality) }
    var hy2 by rememberSaveable(key, stateSaver = jsonSaver<Map<String, Any?>>()) { mutableStateOf(initialHy2) }
    var other by rememberSaveable(key, stateSaver = jsonSaver<Map<String, Any?>>()) { mutableStateOf(initialOptions) }
    var realityYaml by rememberSaveable(key) { mutableStateOf(realityBaseline) }
    var hy2Yaml by rememberSaveable(key) { mutableStateOf(hy2Baseline) }
    var otherYaml by rememberSaveable(key) { mutableStateOf(otherBaseline) }
    var advanced by rememberSaveable(key) { mutableStateOf(initialMode == OTHER) }
    var touched by rememberSaveable(key) { mutableStateOf(listOf<String>()) }
    val saving = LocalEditorSaveState.current.saving
    val type = when (selected) { NodeProtocolOptions.REALITY -> "vless"; NodeProtocolOptions.HY2 -> "hysteria2"; else -> otherType }
    val options = when (selected) { NodeProtocolOptions.REALITY -> reality; NodeProtocolOptions.HY2 -> hy2; else -> other }
    val yaml = when (selected) { NodeProtocolOptions.REALITY -> realityYaml; NodeProtocolOptions.HY2 -> hy2Yaml; else -> otherYaml }
    fun setYaml(value: String) { when (selected) { NodeProtocolOptions.REALITY -> realityYaml = value; NodeProtocolOptions.HY2 -> hy2Yaml = value; else -> otherYaml = value } }
    fun setOptions(value: Map<String, Any?>) {
        when (selected) { NodeProtocolOptions.REALITY -> reality = value; NodeProtocolOptions.HY2 -> hy2 = value; else -> other = value }
    }
    fun change(field: String, value: Any?) {
        // Read snapshot state at event time, including when Compose reuses a field callback.
        val latest = when (selected) { NodeProtocolOptions.REALITY -> reality; NodeProtocolOptions.HY2 -> hy2; else -> other }
        val next = NodeProtocolOptions.patch(latest, field, value)
        setOptions(next)
        setYaml(MihomoNodeOptionsYaml.dump(next))
        touched = (touched + field).distinct()
    }
    val settled = debouncedQuery(yaml)
    val parsed = backgroundValue(settled, null as Result<Map<String, Any?>>?) { runCatching { MihomoNodeOptionsYaml.parse(settled) } }
    val yamlReady = settled == yaml && parsed?.isSuccess == true
    val currentOptions = if (advanced) parsed?.getOrNull().orEmpty() else options
    val errors = NodeProtocolOptions.errors(name, type, server, port,
        if (selected == NodeProtocolOptions.REALITY && !currentOptions.containsKey("reality-opts")) currentOptions + ("reality-opts" to emptyMap<String, Any?>()) else currentOptions)
    val dirty = name != node?.name.orEmpty() || server != node?.server.orEmpty() || port != (node?.port?.toString() ?: "443") ||
        selected != initialMode || otherType != node?.type.orEmpty() || realityYaml != realityBaseline ||
        hy2Yaml != hy2Baseline || otherYaml != otherBaseline
    fun applyYaml() {
        parsed?.getOrNull()?.let { setOptions(NodeProtocolOptions.canonicalOptions(type, it)) }
        touched = (touched + errors.keys).distinct()
    }
    FullScreenEditorDialog(
        title = if (node == null) "新增节点" else "编辑节点", dirty = dirty,
        valid = errors.isEmpty() && (!advanced || yamlReady), onDismiss = onDismiss,
        onSave = {
            if (!saving && errors.isEmpty() && (!advanced || yamlReady)) {
                onSave(name.trim(), type, server.trim(), port.toInt(), if (advanced) currentOptions else options)
            }
        },
    ) {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            // Prevent protocol changes while an invalid YAML draft needs attention.
            SelectField("节点协议", selected,
                if (node == null) listOf(NodeProtocolOptions.REALITY, NodeProtocolOptions.HY2)
                else listOf(NodeProtocolOptions.REALITY, NodeProtocolOptions.HY2, OTHER), enabled = !saving && (!advanced || yamlReady)) {
                if (advanced) applyYaml()
                selected = it
                advanced = it == OTHER
                touched = emptyList()
            }
            NodeTextField("name", "名称", name, { name = it; touched = (touched + "name").distinct() }, errors, touched, enabled = !saving)
            if (selected == OTHER) NodeTextField("type", "Mihomo 协议类型", otherType, { otherType = it; touched = (touched + "type").distinct() }, errors, touched, enabled = !saving)
            NodeTextField("server", "服务器", server, { server = it; touched = (touched + "server").distinct() }, errors, touched, enabled = !saving)
            NodeTextField("port", "端口", port, { port = it; touched = (touched + "port").distinct() }, errors, touched, enabled = !saving)
            if (selected != OTHER) TextButton(onClick = {
                if (advanced) applyYaml()
                else setYaml(MihomoNodeOptionsYaml.dump(options))
                advanced = !advanced
            }, enabled = !advanced || yamlReady) { Text(if (advanced) "返回参数表单" else "高级 YAML") }
            if (advanced) {
                OutlinedTextField(yaml, ::setYaml, Modifier.fillMaxWidth(), enabled = !saving,
                    label = { Text("协议参数 YAML") }, minLines = 8,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                parsed?.exceptionOrNull()?.takeIf { settled == yaml }?.let {
                    Text(it.message ?: "协议参数 YAML 无效", color = MaterialTheme.colorScheme.error)
                }
                if (yamlReady) errors.filterKeys { it !in setOf("name", "type", "server", "port") }.values.forEach {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Text("未在表单中提供的高级参数会完整保留。", style = MaterialTheme.typography.bodySmall)
            } else {
                ProtocolFields(selected, options, ::change, errors, touched, !saving)
            }
            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun ProtocolFields(
    mode: String, options: Map<String, Any?>, onChange: (String, Any?) -> Unit,
    errors: Map<String, String>, touched: List<String>, enabled: Boolean,
) {
    @Composable
    fun field(key: String, label: String, password: Boolean = false, hint: String? = null) {
        var alpnDraft by rememberSaveable(mode, key) { mutableStateOf(NodeProtocolOptions.text(options, key)) }
        NodeTextField(key, label, if (key == "alpn") alpnDraft else NodeProtocolOptions.text(options, key), { raw ->
            if (key == "alpn") alpnDraft = raw
            val value: Any? = when {
                key == "alpn" -> raw.takeIf(String::isNotBlank)?.split(',')?.map(String::trim)?.filter(String::isNotBlank)
                key == "reality-opts.short-id" || key == "password" -> raw
                else -> raw.takeIf(String::isNotBlank)
            }
            onChange(key, value)
        }, errors, touched, password, enabled, hint)
    }
    if (mode == NodeProtocolOptions.REALITY) {
        Text("Reality 参数", style = MaterialTheme.typography.titleSmall)
        field("uuid", "UUID（必填）")
        field("reality-opts.public-key", "公钥 Public Key（必填）")
        field("reality-opts.short-id", "Short ID", hint = "可留空；最多 16 位偶数位十六进制")
        field("servername", "SNI")
        field("client-fingerprint", "客户端指纹", hint = "例如 chrome、firefox；留空使用内核默认值")
        field("flow", "Flow", hint = "通常为 xtls-rprx-vision；可留空")
    } else {
        Text("HY2 认证与混淆", style = MaterialTheme.typography.titleSmall)
        field("password", "认证密码", password = true, hint = "支持完整的 用户名:密码；无认证时可留空")
        SelectField("混淆类型", NodeProtocolOptions.text(options, "obfs").ifBlank { "关闭" }, listOf("关闭", "salamander", "gecko"), enabled = enabled) {
            onChange("obfs", it.takeUnless { it == "关闭" })
        }
        errors["obfs"]?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        if (NodeProtocolOptions.text(options, "obfs").isNotBlank()) field("obfs-password", "混淆密码（必填）", password = true)
        Text("TLS", style = MaterialTheme.typography.titleSmall)
        field("sni", "SNI")
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("跳过证书校验", Modifier.weight(1f))
            Switch(checked = options["skip-cert-verify"] == true, onCheckedChange = { onChange("skip-cert-verify", it) }, enabled = enabled)
        }
        errors["skip-cert-verify"]?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        field("fingerprint", "证书 SHA-256 指纹")
        field("alpn", "ALPN", hint = "多个值以逗号分隔，例如 h3")
        Text("带宽与端口跳跃", style = MaterialTheme.typography.titleSmall)
        field("up", "上行带宽", hint = "例如 30 Mbps；留空使用内核默认值")
        field("down", "下行带宽", hint = "例如 200 Mbps；留空使用内核默认值")
        field("ports", "跳跃端口", hint = "例如 443,8443-8450；填写后优先于单端口")
        field("hop-interval", "跳跃间隔（秒）", hint = "例如 30 或 15-30；留空使用内核默认值")
    }
}

@Composable
private fun NodeTextField(
    key: String, label: String, value: String, onChange: (String) -> Unit,
    errors: Map<String, String>, touched: List<String>, password: Boolean = false,
    enabled: Boolean = true, hint: String? = null,
) {
    var visible by rememberSaveable(key) { mutableStateOf(false) }
    val error = errors[key]?.takeIf { key in touched }
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth(), label = { Text(label) },
        singleLine = true, enabled = enabled, isError = error != null,
        visualTransformation = if (password && !visible) PasswordVisualTransformation() else VisualTransformation.None,
        trailingIcon = if (password) ({
            IconButton(onClick = { visible = !visible }) {
                Icon(if (visible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                    contentDescription = if (visible) "隐藏$label" else "显示$label")
            }
        }) else null,
        supportingText = if (error != null || hint != null) ({ Text(error ?: hint.orEmpty()) }) else null)
}
