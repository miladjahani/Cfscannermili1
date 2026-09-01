[app]
title = Cloudflare Scanner
package.name = cfscanner
package.domain = org.test
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0
requirements = python3,kivy,kivymd
orientation = portrait
osx.python_version = 3
osx.kivy_version = 1.9.1
fullscreen = 0
android.permissions = INTERNET, ACCESS_NETWORK_STATE
android.archs = arm64-v8a, armeabi-v7a
android.accept_sdk_license = True
[buildozer]
log_level = 2
warn_on_root = 1
