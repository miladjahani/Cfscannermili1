[app]

# (str) Title of your application
title = اسکنر کلودفلر

# (str) Package name
package.name = cfpersianscan

# (str) Package domain (needed for android/ios packaging)
package.domain = org.cfscanner

# (str) Source code where the main.py live
source.dir = .

# (list) Source files to include (let empty to include all the files)
source.include_exts = py,png,jpg,jpg,kv,atlas,ttf,otf,json

# (str) Application versioning
version = 1.0.0

# (list) Application requirements
# CRITICAL: Kivy and KivyMD are pinned to known-good, compatible versions.
requirements = python3,kivy==2.2.1,kivymd==1.1.1,requests,urllib3,certifi,chardet,idna,sqlite3,pyjnius

# (str) Presplash / icon (optional, uncomment and provide your own assets)
#presplash.filename = %(source.dir)s/data/presplash.png
#icon.filename = %(source.dir)s/data/icon.png

# (str) Supported orientation (one of landscape, sensorLandscape, portrait or all)
orientation = portrait

# (bool) Indicate if the application should be fullscreen or not
fullscreen = 0

# ---------------------------------------------------------------------------
# ANDROID
# ---------------------------------------------------------------------------

# (list) Permissions
android.permissions = INTERNET, WRITE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE, ACCESS_NETWORK_STATE

# (int) Target Android API, should be as high as possible.
android.api = 33

# (int) Minimum API your APK / AAB will support.
android.minapi = 24

# (str) Android NDK version to use
android.ndk = 25b

# (bool) Use --private data storage (True) or --dir public storage (False)
android.private_storage = True

# (str) Android entry point, default is ok for Kivy-based app
android.entrypoint = org.kivy.android.PythonActivity

# (str) Android app theme, default is ok for Kivy-based app
android.apptheme = "@android:style/Theme.NoTitleBar"

# (list) The Android archs to build for.
# CRITICAL: 64-bit only, as required.
android.archs = arm64-v8a

# (bool) enables Android auto backup feature (Android API >=23)
android.allow_backup = True

# (bool) If True, then automatically accept SDK license
android.accept_sdk_license = True

# (str) python-for-android branch to use, defaults to master
p4a.branch = master

# (bool) Skip byte compile for .py files (speeds up build/debug cycles)
android.no-byte-compile-python = False

# (int) Android logcat filters to use
android.logcat_filters = *:S python:D

# (bool) Copy library instead of making a libpymodules.so
android.copy_libs = 1

# (list) The format used to package the app for release mode (aab or apk).
android.release_artifact = apk

# (list) The format used to package the app for debug mode (apk or aab).
android.debug_artifact = apk


[buildozer]

# (int) Log level (0 = error only, 1 = info, 2 = debug (with command output))
log_level = 2

# (int) Display warning if buildozer is run as root
warn_on_root = 1

# (str) Path to build artifact storage, absolute or relative to spec file
build_dir = ./.buildozer

# (str) Path to build output (i.e. .apk, .aab, .ipa) storage
bin_dir = ./bin
