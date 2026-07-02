#!/bin/bash
# Stop the script immediately if any individual command fails
set -e

APP_NAME="bitbar-qt.app"
DMG_NAME="bitbar-qt.dmg"

echo "===================================================="
echo " Starting Standalone Portable Packaging for Mac... "
echo "===================================================="

# 1. REMOVED MACDEPLOYQT AND DYLIB COPY LOOPS!
# Your static binary completely bypasses /Contents/Frameworks/

# 2. Apply a Free Ad-Hoc Code Signature
# This signs the isolated static binary using your local worker identity,
# preventing macOS from instantly panicking over missing signature IDs.
echo "Applying free local ad-hoc code signature..."
codesign --force --deep --sign - "$APP_NAME"

# 3. Clean up any stale DMG installers from prior runs
if [ -f "$DMG_NAME" ]; then
    echo "Clearing out old artifact..."
    rm "$DMG_NAME"
fi

# 4. Build the fancy, stylized layout using create-dmg
echo "Packaging into fancy distribution DMG..."
create-dmg \
  --volname "Bitbar Installer" \
  --background "./contrib/macdeploy/background.png" \
  --window-pos 200 120 \
  --window-size 500 340 \
  --icon-size 110 \
  --icon "$APP_NAME" 115 155 \
  --app-drop-link 385 155 \
  "$DMG_NAME" \
  "./$APP_NAME"

echo "===================================================="
echo " Deployed Successfully! File: $DMG_NAME              "
echo "===================================================="