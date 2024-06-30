# `appattest-rs`
A Rust crate for validating Apple App Attestations and Assertions, ensuring the integrity and authenticity of apps running on iOS devices.

## Overview
`appattest-rs` offers a Rust-based solution for integrating Apple's App Attestation mechanism into your server-side applications. This allows you to verify that the app communicating with your server is genuine and has not been modified. This crate is particularly useful for enhancing the security of your iOS applications by utilizing Apple's DeviceCheck capabilities.

![DeviceCheck Architecture](https://docs-assets.developer.apple.com/published/dc22cc31ec504d09294006e63caf6ed9/devicecheck-1@2x.png)

## Features
- **Validation of App Attestations**: Ensure that the attestation received from an iOS device is valid and conforms to Apple's guidelines.
- **Assertion Verification**: Verify assertions made by iOS applications to confirm their authenticity.

## References
For more detailed documentation, visit the following resources:
- [Apple Developer: Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [WWDC 2021 - Session 10244](https://developer.apple.com/videos/play/wwdc2021/10244/)

