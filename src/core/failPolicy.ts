import { UranoGuardConfig } from '../types/config';

/** Fail-closed when explicitly requested, or when failOpen is set to false. */
export function isFailClosed(config: Pick<UranoGuardConfig, 'failClosed' | 'failOpen'>): boolean {
    if (config.failClosed === true) return true;
    if (config.failOpen === false) return true;
    return false;
}
