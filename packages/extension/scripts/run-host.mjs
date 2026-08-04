#!/usr/bin/env node
import { configFromEnv, runNativeHost } from '@warrenbrowse/sdk-extension/host';

await runNativeHost(configFromEnv());
