import type { Storage } from 'webextension-polyfill';

export const IS_SESSION_STORAGE_SUPPORTED = 'chrome' in global;

export const sessionStorage: Storage.LocalStorageArea =
    // @ts-expect-error chrome
    IS_SESSION_STORAGE_SUPPORTED ? global.chrome.storage.session : null;
