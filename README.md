# AuthLayer

[![Security & Standards](https://github.com/infocyph/AuthLayer/actions/workflows/security-standards.yml/badge.svg)](https://github.com/infocyph/AuthLayer/actions/workflows/security-standards.yml)
![Packagist Downloads](https://img.shields.io/packagist/dt/infocyph/AuthLayer?color=green\&link=https%3A%2F%2Fpackagist.org%2Fpackages%2Finfocyph%2FAuthLayer)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
![Packagist Version](https://img.shields.io/packagist/v/infocyph/AuthLayer)
![Packagist PHP Version](https://img.shields.io/packagist/dependency-v/infocyph/AuthLayer/php)
![GitHub Code Size](https://img.shields.io/github/languages/code-size/infocyph/AuthLayer)
[![Documentation](https://img.shields.io/badge/Documentation-AuthLayer-blue?logo=readthedocs&logoColor=white)](https://docs.infocyph.com/projects/AuthLayer/en/latest/)

Dependency-free authentication and authorization core for PHP.

## Overview

AuthLayer owns authentication and authorization orchestration, domain contracts, value objects, decisions, audit events, and notification intents.

AuthLayer does not implement or require concrete:

- password hashing
- token signing or encryption
- OTP algorithms
- database persistence
- cache backends
- notification delivery
- HTTP or framework runtime integration

Those concerns belong in bridge packages.

## Package

- Composer: `infocyph/auth-layer`
- Namespace: `Infocyph\AuthLayer`
- PHP: `>=8.4`

## Core Surface

AuthLayer currently provides source modules for:

- accounts and principals
- login and logout orchestration
- sessions and remember-me
- password reset and password change
- email verification
- passwordless flows
- access and refresh token lifecycle
- MFA orchestration
- passkey orchestration
- authorization gates and permission authorizers
- delegation and grants
- device trust and lockout
- audit events and notification intents
- in-memory support stores
- local clock, ID, and security contracts

## Current Status

The package contains:

- concrete contracts and DTOs
- orchestration managers
- in-memory stores for development and testing
- Pest coverage across the main library surface
- PhpBench benchmarks for core authentication, authorization, and support paths

Framework adapters, transport integrations, and concrete crypto or OTP implementations are intentionally out of scope for this package.
