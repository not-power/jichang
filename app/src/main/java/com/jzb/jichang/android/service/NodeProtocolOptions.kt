package com.jzb.jichang.android.service

import com.jzb.jichang.android.model.ProxyNode
import java.net.URI
import java.net.IDN
import java.util.Base64
import java.util.UUID

/** Protocol options stay in the portable map; only keys edited by a form are patched. */
object NodeProtocolOptions {
    const val REALITY = "VLESS Reality"
    const val HY2 = "HY2"

    fun canonicalType(type: String): String = when (val value = type.trim().lowercase()) {
        "hy2" -> "hysteria2"
        else -> value
    }

    fun mode(type: String, options: Map<String, Any?>): String? = when {
        canonicalType(type) == "hysteria2" -> HY2
        canonicalType(type) == "vless" && options.containsKey("reality-opts") -> REALITY
        else -> null
    }

    fun defaults(mode: String): Map<String, Any?> = if (mode == REALITY) linkedMapOf(
        "tls" to true, "client-fingerprint" to "chrome", "flow" to "xtls-rprx-vision",
        "reality-opts" to linkedMapOf("public-key" to "", "short-id" to ""),
    ) else linkedMapOf("password" to "")

    fun canonicalOptions(type: String, options: Map<String, Any?>): LinkedHashMap<String, Any?> = LinkedHashMap(options).apply {
        when (canonicalType(type)) {
            "hysteria2" -> {
                if (!containsKey("sni") && containsKey("servername")) put("sni", get("servername"))
                remove("servername")
            }
            "vless" -> {
                if (!containsKey("servername") && containsKey("sni")) put("servername", remove("sni"))
                if (containsKey("reality-opts")) put("tls", true)
            }
        }
    }

    fun text(options: Map<String, Any?>, key: String): String {
        val value = if (key.startsWith("reality-opts.")) {
            (options["reality-opts"] as? Map<*, *>)?.get(key.substringAfter('.'))
        } else options[key]
        return when (value) {
            null -> ""
            is List<*> -> value.joinToString(", ")
            is Number -> if (value.toDouble() == value.toLong().toDouble()) value.toLong().toString() else value.toString()
            else -> value.toString()
        }
    }

    fun patch(options: Map<String, Any?>, key: String, value: Any?): Map<String, Any?> {
        val result = LinkedHashMap(options)
        if (key.startsWith("reality-opts.")) {
            val nested = linkedMapOf<String, Any?>().apply {
                (options["reality-opts"] as? Map<*, *>)?.forEach { (k, v) -> put(k.toString(), v) }
            }
            val nestedKey = key.substringAfter('.')
            if (value == null) nested.remove(nestedKey) else nested[nestedKey] = value
            result["reality-opts"] = nested
        } else if (value == null) result.remove(key) else result[key] = value
        return result
    }

    /** Validates without expanding ranges (untrusted subscription input can be large). */
    fun firstPort(ports: String): Int {
        val parts = ports.trim().split(',', '/')
        require(parts.size in 1..28 && parts.all { part ->
            Regex("[0-9]+(?:-[0-9]+)?").matches(part.trim()) &&
                part.trim().split('-').all { it.toIntOrNull() in 1..65535 }
        }) { "端口集合须为 1–65535 的端口或范围，最多 28 项，例如 443,8443-8450" }
        return parts.first().trim().substringBefore('-').toInt()
    }

    fun normalize(raw: Map<String, Any?>): LinkedHashMap<String, Any?> {
        val type = canonicalType(raw["type"]?.toString().orEmpty())
        val result = canonicalOptions(type, raw)
        require(type.isNotBlank()) { "请输入协议类型" }
        val server = raw["server"]?.toString()?.trim().orEmpty().removeSurrounding("[", "]")
        require(validServer(server)) { "请输入有效的服务器地址，不含协议和端口" }
        val portValue = raw["port"]
        val port = when (portValue) {
            is Number -> portValue.toInt().takeIf { it.toDouble() == portValue.toDouble() }
            else -> portValue?.toString()?.toIntOrNull()
        }
        val ports = if (type == "hysteria2") raw["ports"]?.toString()?.takeIf(String::isNotBlank) else null
        val hoppingPort = ports?.let(::firstPort)
        require(portValue == null || port in 1..65535) { "端口须为 1–65535" }
        val resolvedPort = port ?: hoppingPort
        require(resolvedPort in 1..65535) { "端口须为 1–65535" }
        result["type"] = type
        result["server"] = server
        result["port"] = resolvedPort
        if (mode(type, result) != null) {
            val errors = errors(result["name"]?.toString()?.takeIf(String::isNotBlank) ?: "node", type, server, resolvedPort.toString(), result)
            require(errors.isEmpty()) { errors.values.first() }
        }
        return result
    }

    fun node(raw: Map<String, Any?>, sourceId: String? = null): ProxyNode {
        val options = normalize(raw)
        val type = options["type"].toString()
        val server = options["server"].toString()
        val port = options["port"] as Int
        val name = options["name"]?.toString()?.replace(Regex("[\\r\\n]+"), " ")?.trim()
            ?.takeIf(String::isNotBlank) ?: "$type $server:$port"
        options["name"] = name
        return ProxyNode(UUID.randomUUID().toString(), sourceId, name, type, server, port, options = options)
    }

    fun validServer(value: String): Boolean {
        if (value.isBlank() || value.any { it.isWhitespace() || it in "/?#@" }) return false
        val host = value.removeSurrounding("[", "]")
        return runCatching {
            if (':' in host) URI("dummy://[$host]").host != null
            else IDN.toASCII(host).let { ascii ->
                ascii.length <= 253 && ascii.removeSuffix(".").split('.').all {
                    it.length in 1..63 && Regex("[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?").matches(it)
                }
            }
        }.getOrDefault(false)
    }

    /** Field IDs also identify the corresponding controls in the editor. */
    fun errors(name: String, type: String, server: String, port: String, options: Map<String, Any?>): Map<String, String> {
        val errors = linkedMapOf<String, String>()
        if (name.isBlank()) errors["name"] = "请输入节点名称"
        if (type.isBlank()) errors["type"] = "请输入协议类型"
        if (!validServer(server.trim())) errors["server"] = "请输入有效的服务器地址，不含协议和端口"
        if (port.toIntOrNull() !in 1..65535) errors["port"] = "端口须为 1–65535"
        when (mode(type, options)) {
            REALITY -> {
                if (!Regex("[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}").matches(text(options, "uuid")))
                    errors["uuid"] = "请输入完整 UUID"
                val key = text(options, "reality-opts.public-key")
                if (!Regex("[A-Za-z0-9_-]{43}=?").matches(key) || runCatching { Base64.getUrlDecoder().decode(key).size != 32 }.getOrDefault(true))
                    errors["reality-opts.public-key"] = "公钥须为 32 字节的 Base64URL 字符串"
                val shortId = text(options, "reality-opts.short-id")
                val rawShortId = (options["reality-opts"] as? Map<*, *>)?.get("short-id")
                if ((rawShortId != null && rawShortId !is String) || !Regex("(?:[0-9a-fA-F]{2}){0,8}").matches(shortId))
                    errors["reality-opts.short-id"] = "Short ID 须为最多 16 位的偶数位十六进制字符串，可留空"
            }
            HY2 -> {
                val obfs = text(options, "obfs")
                if (obfs.isNotBlank() && obfs !in setOf("salamander", "gecko")) errors["obfs"] = "混淆类型须为 salamander 或 gecko"
                if (obfs.isNotBlank() && text(options, "obfs-password").isBlank()) errors["obfs-password"] = "开启混淆时请输入混淆密码"
                val ports = text(options, "ports")
                if (ports.isNotBlank()) runCatching { firstPort(ports) }.exceptionOrNull()?.let { errors["ports"] = it.message.orEmpty() }
                val interval = text(options, "hop-interval")
                if (interval.isNotBlank()) {
                    val parts = interval.split('-').map { it.toLongOrNull() }
                    if (!Regex("[0-9]+(?:-[0-9]+)?").matches(interval) ||
                        parts.any { it == null || it <= 0 || it > Long.MAX_VALUE / 1_000_000_000 } ||
                        (parts.size == 2 && (parts[0] ?: 0L) > (parts[1] ?: 0L)))
                        errors["hop-interval"] = "请输入正整数秒数或单个递增范围，例如 30 或 15-30"
                }
                for (key in listOf("up", "down")) {
                    val bandwidth = text(options, key)
                    val rate = Regex("^[0-9]+(?:\\.[0-9]+)?").find(bandwidth)?.value?.toDoubleOrNull() ?: 0.0
                    if (bandwidth.isNotBlank() && (!Regex("[0-9]+(?:\\.[0-9]+)?(?:\\s*[kmg]?bps)?", RegexOption.IGNORE_CASE).matches(bandwidth) ||
                            !rate.isFinite() || rate <= 0))
                        errors[key] = "请输入正数带宽，例如 30 或 30 Mbps"
                }
                val fingerprint = text(options, "fingerprint").replace(":", "")
                if (fingerprint.isNotBlank() && !Regex("[0-9a-fA-F]{64}").matches(fingerprint)) errors["fingerprint"] = "SHA-256 指纹须为 64 位十六进制，可包含冒号"
                val alpn = options["alpn"]
                if (alpn != null && (alpn !is List<*> || alpn.any { it !is String })) errors["alpn"] = "ALPN 须为字符串列表，例如 [h3]"
                if (options["skip-cert-verify"] != null && options["skip-cert-verify"] !is Boolean) errors["skip-cert-verify"] = "证书校验开关须为 true 或 false"
            }
        }
        return errors
    }
}
