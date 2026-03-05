/**
 * frida-ssl-unpinning.js
 * Bypass SSL Pinning universel pour Android 7+
 *
 * Couvre :
 *   - javax.net.ssl.SSLContext (TrustManager generique)
 *   - OkHttp3 CertificatePinner
 *   - TrustManagerImpl.verifyChain (Android 7+)
 *   - Conscrypt / Platform TrustManager
 *   - WebView SSL errors
 *
 * Usage :
 *   frida -U -f com.target.app -l frida-ssl-unpinning.js --no-pause
 */

setTimeout(function () {
    Java.perform(function () {
        console.log("[*] Demarrage du bypass SSL pinning...");

        // =========================================================
        // 1. SSLContext.init() - TrustManager generique
        // =========================================================
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");

            var TrustManager = Java.registerClass({
                name: "dev.audit.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () {
                        return [];
                    },
                },
            });

            var TrustManagers = [TrustManager.$new()];

            var SSLContext_init = SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            );

            SSLContext_init.implementation = function (km, tm, sr) {
                console.log("[+] SSLContext.init() intercepte");
                SSLContext_init.call(this, km, TrustManagers, sr);
            };
            console.log("[+] SSLContext.init() bypass OK");
        } catch (err) {
            console.log("[-] SSLContext.init() : " + err);
        }

        // =========================================================
        // 2. OkHttp3 CertificatePinner
        // =========================================================
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");

            // check(String, List)
            CertificatePinner.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function (hostname, peerCertificates) {
                console.log("[+] OkHttp3 CertificatePinner.check() bypass : " + hostname);
            };
            console.log("[+] OkHttp3 CertificatePinner bypass OK");
        } catch (err) {
            console.log("[-] OkHttp3 CertificatePinner : " + err);
        }

        // Variante OkHttp3 avec check$okhttp
        try {
            var CertificatePinner2 = Java.use("okhttp3.CertificatePinner");
            CertificatePinner2["check$okhttp"].implementation = function (
                hostname,
                cleanedCerts
            ) {
                console.log("[+] OkHttp3 check$okhttp bypass : " + hostname);
            };
            console.log("[+] OkHttp3 check$okhttp bypass OK");
        } catch (err) {
            // Non present dans toutes les versions, pas une erreur critique
        }

        // =========================================================
        // 3. TrustManagerImpl.verifyChain (Android 7+)
        // =========================================================
        try {
            var TrustManagerImpl = Java.use(
                "com.android.org.conscrypt.TrustManagerImpl"
            );

            TrustManagerImpl.verifyChain.implementation = function (
                untrustedChain,
                trustAnchorChain,
                host,
                clientAuth,
                ocspData,
                tlsSctData
            ) {
                console.log("[+] TrustManagerImpl.verifyChain() bypass : " + host);
                return untrustedChain;
            };
            console.log("[+] TrustManagerImpl.verifyChain() bypass OK");
        } catch (err) {
            console.log("[-] TrustManagerImpl.verifyChain() : " + err);
        }

        // =========================================================
        // 4. Conscrypt / Platform TrustManager
        // =========================================================
        try {
            var ConscryptPlatform = Java.use(
                "org.conscrypt.Platform"
            );
            ConscryptPlatform.checkServerTrusted.overload(
                "javax.net.ssl.X509TrustManager",
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String",
                "com.android.org.conscrypt.AbstractConscryptSocket"
            ).implementation = function (tm, chain, authType, socket) {
                console.log("[+] Conscrypt Platform.checkServerTrusted() bypass");
            };
            console.log("[+] Conscrypt Platform bypass OK");
        } catch (err) {
            // Conscrypt peut ne pas etre present
        }

        // =========================================================
        // 5. WebViewClient onReceivedSslError
        // =========================================================
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function (
                webView,
                handler,
                error
            ) {
                console.log("[+] WebViewClient SSL error bypass");
                handler.proceed();
            };
            console.log("[+] WebViewClient SSL bypass OK");
        } catch (err) {
            console.log("[-] WebViewClient : " + err);
        }

        // =========================================================
        // 6. HostnameVerifier bypass
        // =========================================================
        try {
            var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
            var SSLSession = Java.use("javax.net.ssl.SSLSession");

            var MyVerifier = Java.registerClass({
                name: "dev.audit.HostnameVerifier",
                implements: [HostnameVerifier],
                methods: {
                    verify: function (hostname, session) {
                        return true;
                    },
                },
            });

            var HttpsURLConnection = Java.use(
                "javax.net.ssl.HttpsURLConnection"
            );
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (
                verifier
            ) {
                console.log("[+] HttpsURLConnection HostnameVerifier bypass");
                HttpsURLConnection.setDefaultHostnameVerifier.call(
                    this,
                    MyVerifier.$new()
                );
            };
            console.log("[+] HostnameVerifier bypass OK");
        } catch (err) {
            console.log("[-] HostnameVerifier : " + err);
        }

        console.log("[*] Bypass SSL pinning termine.");
    });
}, 0);
