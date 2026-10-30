package com.jzb.jichang.android.service

import com.google.gson.Gson
import com.jzb.jichang.android.model.ParseResult
import com.jzb.jichang.android.model.ProxyNode
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Parses subscription bodies locally. Unsupported entries are counted, never silently exported. */
class SubscriptionParser {
    fun parse(input: String, sourceId: String? = null): ParseResult {
        val text = decodeSubscriptionBody(input.trim())
        if (text.isBlank()) return ParseResult(emptyList(), 0)

        parseClashYaml(text, sourceId)?.let { return it }

        val lines = text.lineSequence().map(String::trim)
            .filter { it.isNotEmpty() && !it.startsWith('#') }
        val parsed = mutableListOf<ProxyNode>()
        var skipped = 0
        for (line in lines) {
            val node = runCatching { parseUri(line, sourceId) }.getOrNull()
                ?: runCatching { parseSurgeLine(line, sourceId) }.getOrNull()
            if (node == null) skipped++ else parsed += node
        }
        return ParseResult(parsed, skipped)
    }

    private fun decodeSubscriptionBody(value: String): String {
        if (value.startsWith("proxies:") || value.startsWith("port:") || value.contains("\nproxies:")) return value
        val compact = value.replace("\\s".toRegex(), "")
        if (compact.length < 16 || compact.any { it !in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-" }) return value
        val decoded = runCatching {
            val normalized = compact.replace('-', '+').replace('_', '/')
            val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
            String(runCatching { Base64.getDecoder().decode(padded) }.getOrElse { Base64.getUrlDecoder().decode(padded) }, StandardCharsets.UTF_8)
        }.getOrNull() ?: return value
        return if (decoded.contains("://") || decoded.contains("proxies:")) decoded else value
    }

    private fun parseClashYaml(text: String, sourceId: String?): ParseResult? {
        if (!text.contains("proxies:")) return null
        return runCatching {
            val options = LoaderOptions().apply {
                maxAliasesForCollections = 20
                codePointLimit = 4 * 1024 * 1024
            }
            @Suppress("UNCHECKED_CAST")
            val root = Yaml(SafeConstructor(options)).load<Any?>(text) as? Map<String, Any?> ?: return null
            val rawNodes = root["proxies"] as? List<*> ?: return null
            var skipped = 0
            val nodes = rawNodes.mapNotNull { item ->
                @Suppress("UNCHECKED_CAST")
                val map = (item as? Map<*, *>)?.entries?.associate { it.key.toString() to it.value } ?: run {
                    skipped++; return@mapNotNull null
                }
                runCatching { NodeProtocolOptions.node(map, sourceId) }.getOrElse { skipped++; null }
            }
            ParseResult(nodes, skipped)
        }.getOrNull()
    }

    private fun parseUri(line: String, sourceId: String?): ProxyNode? {
        if (line.startsWith("vmess://", true)) return parseVmess(line, sourceId)
        if (line.startsWith("ss://", true)) return parseShadowsocks(line, sourceId)
        if (line.startsWith("ssr://", true)) return parseShadowsocksR(line, sourceId)
        if (line.startsWith("hy2://", true) || line.startsWith("hysteria2://", true)) return parseHysteria2(line, sourceId)
        val uri = URI(line)
        val type = uri.scheme?.lowercase() ?: return null
        if (type !in setOf("vless", "trojan", "hysteria", "tuic", "anytls", "socks", "socks5", "http")) return null
        val host = uri.host?.removeSurrounding("[", "]") ?: return null
        val port = uri.port.takeIf { it in 1..65535 } ?: return null
        val query = parseQuery(uri.rawQuery)
        val userInfo = uri.rawUserInfo?.split(':', limit = 2).orEmpty()
        val username = userInfo.getOrNull(0)?.decodeUri().orEmpty()
        val password = userInfo.getOrNull(1)?.decodeUri().orEmpty()
        val name = uri.rawFragment?.decodeUri()?.takeIf(String::isNotBlank) ?: "$type $host:$port"
        val normalizedType = if (type == "socks") "socks5" else type
        val fields = linkedMapOf<String, Any?>("type" to normalizedType, "name" to name, "server" to host, "port" to port)
        when (normalizedType) {
            "vless" -> {
                fields["uuid"] = username
                fields["tls"] = query["security"] !in setOf(null, "", "none")
                fields["flow"] = query["flow"]
                addTLS(fields, query)
                addTransport(fields, query)
                if (query["security"] == "reality") {
                    fields["reality-opts"] = linkedMapOf("public-key" to query["pbk"], "short-id" to (query["sid"] ?: ""))
                }
            }
            "trojan" -> { fields["password"] = username; fields["tls"] = true; addTLS(fields, query); addTransport(fields, query) }
            "hysteria" -> {
                fields["password"] = query["auth"] ?: username
                fields["auth-str"] = query["auth"] ?: username
                fields["tls"] = true; addTLS(fields, query)
                query["obfs"]?.let { fields["obfs"] = it }
                query["upmbps"]?.toIntOrNull()?.let { fields["up"] = it }
                query["downmbps"]?.toIntOrNull()?.let { fields["down"] = it }
            }
            "tuic" -> {
                fields["uuid"] = username; fields["password"] = password; fields["tls"] = true; addTLS(fields, query)
                fields["congestion-controller"] = query["congestion_control"] ?: "cubic"
                fields["udp-relay-mode"] = query["udp_relay_mode"] ?: "native"
            }
            "anytls" -> { fields["password"] = username; fields["tls"] = true; addTLS(fields, query) }
            "socks5", "http" -> { fields["username"] = username; fields["password"] = password }
        }
        return createNode(fields, sourceId)
    }

    private fun parseHysteria2(line: String, sourceId: String?): ProxyNode? {
        // URI rejects bracketed IPv6 with a multi-port authority before host can be read.
        val body = line.substringAfter("://")
        val authority = body.takeWhile { it !in "/?#" }
        val uri = URI("hy2://placeholder" + body.substring(authority.length))
        val endpoint = authority.substringAfterLast('@')
        val host: String
        val portText: String
        if (endpoint.startsWith('[')) {
            val end = endpoint.indexOf(']')
            if (end < 0) return null
            host = endpoint.substring(1, end)
            val suffix = endpoint.substring(end + 1)
            if (suffix.isNotEmpty() && !suffix.startsWith(':')) return null
            portText = suffix.removePrefix(":")
            if (suffix == ":") return null
        } else {
            host = endpoint.substringBefore(':')
            portText = endpoint.substringAfter(':', "")
            if (endpoint.endsWith(':')) return null
        }
        val query = parseQuery(uri.rawQuery)
        val addressPort = portText.takeIf(String::isNotBlank)?.let(NodeProtocolOptions::firstPort) ?: 443
        val addressPorts = portText.takeIf { ',' in it || '-' in it || '/' in it }
        val fields = linkedMapOf<String, Any?>(
            "type" to "hysteria2", "server" to host, "port" to addressPort,
            "name" to (uri.rawFragment?.decodeUri()?.takeIf(String::isNotBlank) ?: "HY2 $host:$addressPort"),
            "password" to (if ('@' in authority) authority.substringBeforeLast('@').decodeUri() else ""),
        )
        for (key in listOf("insecure", "allowInsecure")) {
            if (query.containsKey(key) && query[key]?.lowercase() !in setOf("0", "1", "true", "false")) return null
        }
        addTLS(fields, query)
        fields.remove("client-fingerprint")
        fields["sni"] = fields.remove("servername")
        fields["ports"] = query["ports"] ?: query["mport"] ?: addressPorts
        for (key in listOf("obfs", "obfs-password", "hop-interval", "up", "down")) query[key]?.let { fields[key] = it }
        query["pinSHA256"]?.let { fields["fingerprint"] = it }
        query["ech"]?.let { fields["ech-opts"] = linkedMapOf("enable" to true, "config" to it) }
        // Invalid optional numeric values must not silently become a different connection.
        val validation = NodeProtocolOptions.errors(fields["name"].toString(), "hysteria2", host, addressPort.toString(), fields)
        if (validation.keys.any { it in setOf("ports", "hop-interval", "up", "down") }) return null
        return createNode(fields, sourceId)
    }

    private fun parseShadowsocks(line: String, sourceId: String?): ProxyNode? {
        val body = line.removePrefix("ss://")
        val noFragment = body.substringBefore('#')
        val uriQuery = runCatching { URI(line).rawQuery }.getOrNull()
        if (uriQuery?.split('&')?.any { it.substringBefore('=').equals("plugin", true) } == true) return null
        val name = body.substringAfter('#', "").decodeUri().ifBlank { "Shadowsocks" }
        val at = noFragment.lastIndexOf('@')
        val authority: String
        val credential: String
        if (at >= 0) {
            credential = noFragment.substring(0, at).decodeUri()
            authority = noFragment.substring(at + 1).substringBefore('/')
        } else {
            val decoded = decodeBase64(noFragment.substringBefore('/')) ?: return null
            val split = decoded.lastIndexOf('@')
            if (split < 0) return null
            credential = decoded.substring(0, split); authority = decoded.substring(split + 1)
        }
        val fieldsPair = credential.split(':', limit = 2)
        val decodedCredential = if (fieldsPair.size == 2) credential else decodeBase64(credential) ?: return null
        val decodedFields = decodedCredential.split(':', limit = 2)
        if (decodedFields.size != 2) return null
        val hostPort = parseHostPort(authority) ?: return null
        val fields = linkedMapOf<String, Any?>(
            "type" to "ss", "name" to name, "server" to hostPort.first, "port" to hostPort.second,
            "cipher" to decodedFields[0], "password" to decodedFields[1]
        )
        return createNode(fields, sourceId)
    }

    private fun parseShadowsocksR(line: String, sourceId: String?): ProxyNode? {
        val decoded = decodeBase64(line.substringAfter("ssr://", "")) ?: return null
        val serverInfo = decoded.substringBefore("/?")
        val parts = serverInfo.split(':', limit = 6)
        if (parts.size != 6) return null
        val server = parts[0].removeSurrounding("[", "]").takeIf(String::isNotBlank) ?: return null
        val port = parts[1].toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        val password = decodeBase64(parts[5]) ?: return null
        val query = parseQuery(decoded.substringAfter("/?", ""))
        val name = query["remarks"]?.let(::decodeBase64)?.takeIf(String::isNotBlank) ?: "SSR $server:$port"
        val fields = linkedMapOf<String, Any?>(
            "type" to "ssr", "name" to name, "server" to server, "port" to port,
            "cipher" to parts[3], "password" to password, "protocol" to parts[2], "obfs" to parts[4],
        )
        query["obfsparam"]?.let(::decodeBase64)?.let { fields["obfs-param"] = it }
        query["protoparam"]?.let(::decodeBase64)?.let { fields["protocol-param"] = it }
        return createNode(fields, sourceId)
    }

    private fun parseVmess(line: String, sourceId: String?): ProxyNode? {
        val decoded = decodeBase64(line.substringAfter("vmess://")) ?: return null
        val json = runCatching { Gson().fromJson(decoded, Map::class.java) }.getOrNull() ?: return null
        val server = json["add"]?.toString() ?: return null
        val port = json["port"]?.toString()?.toIntOrNull() ?: return null
        val fields = linkedMapOf<String, Any?>(
            "type" to "vmess", "name" to (json["ps"]?.toString() ?: "VMess $server:$port"),
            "server" to server, "port" to port, "uuid" to json["id"]?.toString().orEmpty(),
            "alterId" to (json["aid"]?.toString()?.toIntOrNull() ?: 0),
            "cipher" to (json["scy"]?.toString()?.ifBlank { "auto" } ?: "auto")
        )
        val network = json["net"]?.toString()
        if (!network.isNullOrBlank() && network != "tcp") addTransport(fields, mapOf("type" to network, "host" to json["host"]?.toString(), "path" to json["path"]?.toString()))
        if (json["tls"]?.toString()?.equals("tls", true) == true) {
            fields["tls"] = true
            fields["servername"] = json["sni"]?.toString()?.ifBlank { json["host"]?.toString() }
            fields["client-fingerprint"] = json["fp"]?.toString()
        }
        return createNode(fields, sourceId)
    }

    private fun parseSurgeLine(line: String, sourceId: String?): ProxyNode? {
        val separator = line.indexOf('=')
        if (separator <= 0) return null
        val name = line.substring(0, separator).trim().trim('"', '\'')
        val pieces = line.substring(separator + 1).split(',').map(String::trim)
        if (pieces.size < 3) return null
        val type = when (pieces[0].lowercase()) {
            "ss", "shadowsocks" -> "ss"
            "vmess" -> "vmess"
            "vless" -> "vless"
            "trojan" -> "trojan"
            "hysteria2", "hysteria2-over-quic" -> "hysteria2"
            else -> return null
        }
        val host = pieces[1].removeSurrounding("[", "]")
        val port = pieces[2].toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        val fields = linkedMapOf<String, Any?>("type" to type, "name" to name, "server" to host, "port" to port)
        val params = pieces.drop(3).mapNotNull { part ->
            val i = part.indexOf('='); if (i <= 0) null else part.substring(0, i).trim().lowercase() to part.substring(i + 1).trim().trim('"', '\'')
        }.toMap()
        when (type) {
            "ss" -> { fields["cipher"] = params["encrypt-method"] ?: params["method"]; fields["password"] = params["password"] }
            "vmess", "vless" -> { fields["uuid"] = params["username"] ?: params["password"]; fields["tls"] = params["tls"] == "true"; fields["servername"] = params["sni"] ?: params["servername"]; addTransport(fields, params.mapKeys { if (it.key == "ws-path") "path" else it.key }.plus("type" to if (params["ws"] == "true") "ws" else "tcp")) }
            "trojan" -> { fields["password"] = params["password"]; fields["tls"] = true; fields["servername"] = params["sni"] ?: params["servername"] }
            "hysteria2" -> { fields["password"] = params["password"]; fields["tls"] = true; fields["servername"] = params["sni"] ?: params["servername"] }
        }
        return createNode(fields, sourceId)
    }

    private fun addTLS(fields: MutableMap<String, Any?>, query: Map<String, String?>) {
        fields["servername"] = query["sni"] ?: query["peer"]
        fields["alpn"] = query["alpn"]?.split(',')?.map(String::trim)?.filter(String::isNotBlank)
        fields["client-fingerprint"] = query["fp"]
        val insecure = query["allowInsecure"] ?: query["insecure"]
        if (insecure != null) fields["skip-cert-verify"] = insecure.equals("true", true) || insecure == "1"
    }

    private fun addTransport(fields: MutableMap<String, Any?>, query: Map<String, String?>) {
        val transport = query["type"] ?: query["network"] ?: return
        if (transport == "tcp" || transport.isBlank()) return
        fields["network"] = transport
        when (transport) {
            "ws" -> fields["ws-opts"] = linkedMapOf("path" to (query["path"] ?: "/"), "headers" to linkedMapOf("Host" to query["host"]))
            "grpc" -> fields["grpc-opts"] = linkedMapOf("grpc-service-name" to (query["serviceName"] ?: query["path"]), "grpc-authority" to query["authority"])
            "http", "httpupgrade" -> fields["http-opts"] = linkedMapOf("path" to listOf(query["path"] ?: "/"), "headers" to linkedMapOf("Host" to query["host"]))
        }
    }

    private fun createNode(fields: Map<String, Any?>, sourceId: String?): ProxyNode? {
        return runCatching { NodeProtocolOptions.node(fields, sourceId) }.getOrNull()
    }

    private fun parseQuery(raw: String?): Map<String, String?> = raw.orEmpty().split('&').filter(String::isNotBlank).associate { token ->
        val parts = token.split('=', limit = 2); parts[0].decodeUri() to parts.getOrNull(1)?.decodeUri()
    }

    private fun parseHostPort(authority: String): Pair<String, Int>? {
        val uri = runCatching { URI("dummy://$authority") }.getOrNull() ?: return null
        val host = uri.host?.removeSurrounding("[", "]") ?: return null
        val port = uri.port.takeIf { it in 1..65535 } ?: return null
        return host to port
    }

    private fun decodeBase64(value: String): String? = runCatching {
        val normalized = value.replace('-', '+').replace('_', '/')
        val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
        String(runCatching { Base64.getDecoder().decode(padded) }.getOrElse { Base64.getUrlDecoder().decode(padded) }, StandardCharsets.UTF_8)
    }.getOrNull()

    private fun String.decodeUri(): String = runCatching { URLDecoder.decode(replace("+", "%2B"), StandardCharsets.UTF_8.name()) }.getOrDefault(this)
}
