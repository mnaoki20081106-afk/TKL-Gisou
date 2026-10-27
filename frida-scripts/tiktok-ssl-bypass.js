//Universal Android SSL Pinning Bypass #1 — Java TrustManager
Java.perform(function () {
    try {
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        if (ApiClient.checkTrustedRecursive) {
            logger("[*][+] Hooked checkTrustedRecursive")
            ApiClient.checkTrustedRecursive.implementation = function (a1, a2, a3, a4, a5, a6) {
                var k = array_list.$new();
                return k;
            }
        } else {
            logger("[*][-] checkTrustedRecursive not Found")
        }
    } catch (e) {
        logger("[*][-] Failed to hook checkTrustedRecursive")
    }
});


//Universal Android SSL Pinning Bypass #2 — SSLContext.init
Java.perform(function () {
    try {
        const x509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const sSLContext = Java.use("javax.net.ssl.SSLContext");
        const TrustManager = Java.registerClass({
            implements: [x509TrustManager],
            methods: {
                checkClientTrusted(chain, authType) {
                },
                checkServerTrusted(chain, authType) {
                },
                getAcceptedIssuers() {
                    return [];
                },
            },
            name: "com.leftenter.tiktok",
        });
        const TrustManagers = [TrustManager.$new()];
        const SSLContextInit = sSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
        SSLContextInit.implementation = function (keyManager, trustManager, secureRandom) {
            SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
        };
        logger("[*][+] Hooked SSLContextInit")
    } catch (e) {
        logger("[*][-] Failed to hook SSLContextInit")
    }
})

//Universal Android SSL Pinning Bypass #3 — WebView onReceivedSslError
Java.perform(function () {
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.overload(
            "android.webkit.WebView",
            "android.webkit.SslErrorHandler",
            "android.net.http.SslError"
        ).implementation = function (webView, handler, error) {
            handler.proceed();
        };
        logger("[*][+] Hooked WebViewClient.onReceivedSslError");
    } catch (e) {
        logger("[*][-] Failed to hook WebViewClient.onReceivedSslError: " + e);
    }
});

//Bypass #4 — Locale.getDefault → ja_JP (forces sys_region=JP in TTNet)
Java.perform(function () {
    try {
        var Locale = Java.use("java.util.Locale");
        Locale.getDefault.overload().implementation = function () {
            return Locale.JAPAN.value;
        };
        logger("[*][+] Hooked Locale.getDefault → ja_JP");
    } catch (e) {
        logger("[*][-] Failed to hook Locale.getDefault: " + e);
    }
});

function logger(message) {
    console.log(message);
    Java.perform(function () {
        var Log = Java.use("android.util.Log");
        Log.v("TIKTOK_SSL_PINNING_BYPASS", message);
    });
}
