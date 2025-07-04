// Copyright (C) 2019-2022 Intel Corporation
// Copyright (C) CVAT.ai Corporation
//
// SPDX-License-Identifier: MIT

import FormData from 'form-data';
import store from 'store';
import Axios, { AxiosError, AxiosResponse } from 'axios';
import * as tus from 'tus-js-client';
import { ChunkQuality } from 'cvat-data';

import './axios-config';
import { axiosTusHttpStack } from './axios-tus';
import {
    SerializedLabel, SerializedAnnotationFormats, ProjectsFilter,
    SerializedProject, SerializedTask, TasksFilter, SerializedUser, SerializedOrganization,
    SerializedAbout, SerializedRemoteFile, SerializedUserAgreement,
    SerializedRegister, JobsFilter, SerializedJob, SerializedGuide, SerializedAsset, SerializedAPISchema,
    SerializedInvitationData, SerializedCloudStorage, SerializedFramesMetaData, SerializedCollection,
    SerializedQualitySettingsData, APIQualitySettingsFilter, SerializedQualityConflictData, APIQualityConflictsFilter,
    SerializedQualityReportData, APIQualityReportsFilter, APIAnalyticsEventsFilter, APIConsensusSettingsFilter,
    SerializedRequest, SerializedJobValidationLayout, SerializedTaskValidationLayout, SerializedConsensusSettingsData,
} from './server-response-types';
import { PaginatedResource, UpdateStatusData } from './core-types';
import { Request } from './request';
import { Storage } from './storage';
import { SerializedEvent } from './event';
import { RQStatus, StorageLocation, WebhookSourceType } from './enums';
import { isEmail, isResourceURL } from './common';
import config from './config';
import { ServerError } from './exceptions';

type Params = {
    org: number | string,
    location?: StorageLocation,
    cloud_storage_id?: number,
    format?: string,
    filename?: string,
    action?: string,
    save_images?: boolean,
};

tus.defaultOptions.storeFingerprintForResuming = false;

function enableOrganization(): { org: string } {
    return { org: config.organization.organizationSlug || '' };
}

function configureStorage(storage: Storage, useDefaultLocation = false): Partial<Params> {
    return {
        ...(!useDefaultLocation ? {
            location: storage.location,
            ...(storage.cloudStorageId ? {
                cloud_storage_id: storage.cloudStorageId,
            } : {}),
        } : {}),
    };
}

function fetchAll(url, filter = {}): Promise<any> {
    const pageSize = 500;
    const result = {
        count: 0,
        results: [],
    };
    return new Promise((resolve, reject) => {
        Axios.get(url, {
            params: {
                ...filter,
                page_size: pageSize,
                page: 1,
            },
        }).then((initialData) => {
            const { count, results } = initialData.data;
            result.results = result.results.concat(results);
            result.count = result.results.length;

            if (count <= pageSize) {
                resolve(result);
                return;
            }

            const pages = Math.ceil(count / pageSize);
            const promises = Array(pages).fill(0).map((_: number, i: number) => {
                if (i) {
                    return Axios.get(url, {
                        params: {
                            ...filter,
                            page_size: pageSize,
                            page: i + 1,
                        },
                    });
                }

                return Promise.resolve(null);
            });

            Promise.all(promises).then((responses: AxiosResponse<any, any>[]) => {
                responses.forEach((resp) => {
                    if (resp) {
                        result.results = result.results.concat(resp.data.results);
                    }
                });

                // removing possible duplicates
                const obj = result.results.reduce((acc: Record<string, any>, item: any) => {
                    acc[item.id] = item;
                    return acc;
                }, {});

                result.results = Object.values(obj);
                result.count = result.results.length;

                resolve(result);
            }).catch((error) => reject(error));
        }).catch((error) => reject(error));
    });
}

async function chunkUpload(file: File, uploadConfig): Promise<{ uploadSentSize: number; filename: string }> {
    const {
        endpoint, chunkSize, totalSize, onUpdate, metadata, totalSentSize,
    } = uploadConfig;
    const uploadResult = { uploadSentSize: 0, filename: file.name };
    return new Promise((resolve, reject) => {
        const upload = new tus.Upload(file, {
            endpoint,
            metadata: {
                filename: file.name,
                filetype: file.type,
                ...metadata,
            },
            httpStack: axiosTusHttpStack,
            chunkSize,
            retryDelays: [2000, 4000, 8000, 16000, 32000, 64000],
            onShouldRetry(err: tus.DetailedError | Error): boolean {
                if (err instanceof tus.DetailedError) {
                    const { originalResponse } = (err as tus.DetailedError);
                    const code = (originalResponse?.getStatus() || 0);

                    // do not retry if (code >= 400 && code < 500) is default tus behaviour
                    // retry if code === 409 or 423 is default tus behaviour
                    // additionally handle codes 429 and 0
                    return !(code >= 400 && code < 500) || [409, 423, 429, 0].includes(code);
                }

                return false;
            },
            onError(error) {
                reject(error);
            },
            onProgress(bytesUploaded) {
                if (onUpdate && Number.isInteger(totalSentSize) && Number.isInteger(totalSize)) {
                    const currentUploadedSize = totalSentSize + bytesUploaded;
                    const percentage = currentUploadedSize / totalSize;
                    onUpdate(percentage);
                }
            },
            onAfterResponse(request, response) {
                const uploadFilename = response.getHeader('Upload-Filename');
                if (uploadFilename) uploadResult.filename = uploadFilename;
            },
            onSuccess() {
                resolve({
                    ...uploadResult,
                    uploadSentSize: file.size,
                });
            },
        });
        upload.start();
    });
}

function filterPythonTraceback(data: string): string {
    if (typeof data === 'string' && data.trim().startsWith('Traceback')) {
        const lastRow = data.split('\n').findLastIndex((str) => str.trim().length);
        let errorText = `${data.split('\n').slice(lastRow, lastRow + 1)[0]}`;
        if (errorText.includes('CvatDatasetNotFoundError')) {
            errorText = errorText.replace(/.*CvatDatasetNotFoundError: /, '');
        }
        return errorText;
    }

    return data;
}

function generateError(errorData: AxiosError): ServerError {
    if (errorData.response) {
        if (errorData.response.status >= 500 && typeof errorData.response.data === 'string') {
            return new ServerError(
                filterPythonTraceback(errorData.response.data),
                errorData.response.status,
            );
        }

        if (errorData.response.status >= 400 && errorData.response.data) {
            // serializer.ValidationError

            if (Array.isArray(errorData.response.data)) {
                return new ServerError(
                    errorData.response.data.join('\n\n'),
                    errorData.response.status,
                );
            }

            if (typeof errorData.response.data === 'object') {
                if ('rq_id' in errorData.response.data) {
                    return new ServerError(
                        `A request with this identifier is already being processed (${errorData.response.data.rq_id})`,
                        errorData.response.status,
                    );
                }

                const generalFields = ['non_field_errors', 'detail', 'message'];
                const generalFieldsHelpers = {
                    'Invalid token.': 'Not authenticated request, try to login again',
                };

                for (const field of generalFields) {
                    if (field in errorData.response.data) {
                        const message = errorData.response.data[field].toString();
                        return new ServerError(
                            generalFieldsHelpers[message] || message,
                            errorData.response.status,
                        );
                    }
                }

                // serializers fields
                const message = Object.keys(errorData.response.data).map((key) => (
                    `**${key}**: ${errorData.response.data[key].toString()}`
                )).join('\n\n');
                return new ServerError(message, errorData.response.status);
            }

            // errors with string data
            if (typeof errorData.response.data === 'string') {
                return new ServerError(errorData.response.data, errorData.response.status);
            }
        }

        // default handling
        return new ServerError(
            errorData.response.statusText || errorData.message,
            errorData.response.status,
        );
    }

    // Server is unavailable (no any response)
    const message = `${errorData.message}.`; // usually is "Error Network"
    return new ServerError(message, 0);
}

function prepareData(details) {
    const data = new FormData();
    for (const [key, value] of Object.entries(details)) {
        if (Array.isArray(value)) {
            value.forEach((element, idx) => {
                data.append(`${key}[${idx}]`, element);
            });
        } else {
            data.set(key, value);
        }
    }
    return data;
}

class WorkerWrappedAxios {
    constructor() {
        const worker = new Worker(new URL('./download.worker', import.meta.url));
        const requests = {};
        let requestId = 0;

        worker.onmessage = (e) => {
            if (e.data.id in requests) {
                try {
                    if (e.data.isSuccess) {
                        requests[e.data.id].resolve({ data: e.data.responseData, headers: e.data.headers });
                    } else {
                        requests[e.data.id].reject(new AxiosError(e.data.message, e.data.code));
                    }
                } finally {
                    delete requests[e.data.id];
                }
            }
        };

        worker.onerror = () => {
            throw new Error('Unexpected download worker error');
        };

        function getRequestId(): number {
            return requestId++;
        }

        async function get(url: string, requestConfig) {
            return new Promise((resolve, reject) => {
                const newRequestId = getRequestId();
                requests[newRequestId] = { resolve, reject };
                worker.postMessage({
                    url,
                    config: requestConfig,
                    id: newRequestId,
                });
            });
        }

        Object.defineProperties(
            this,
            Object.freeze({
                get: {
                    value: get,
                    writable: false,
                },
            }),
        );
    }
}

const workerAxios = new WorkerWrappedAxios();
Axios.interceptors.request.use((reqConfig) => {
    if ('params' in reqConfig && 'org' in reqConfig.params) {
        return reqConfig;
    }

    const organization = enableOrganization();
    // for users when organization is unset
    // we are interested in getting all the users,
    // not only those who are not in any organization
    if (reqConfig.url.endsWith('/users') && !organization.org) {
        return reqConfig;
    }

    if (reqConfig.url.endsWith('/limits')) {
        return reqConfig;
    }

    // we want to get invitations from all organizations
    const { backendAPI } = config;
    const getInvitations = reqConfig.url.endsWith('/invitations') && reqConfig.method === 'get';
    const acceptDeclineInvitation = reqConfig.url.startsWith(`${backendAPI}/invitations`) &&
                                    (reqConfig.url.endsWith('/accept') || reqConfig.url.endsWith('/decline'));
    if (getInvitations || acceptDeclineInvitation) {
        return reqConfig;
    }

    if (isResourceURL(reqConfig.url)) {
        return reqConfig;
    }

    reqConfig.params = { ...organization, ...(reqConfig.params || {}) };
    return reqConfig;
});

Axios.interceptors.response.use((response) => {
    if (isResourceURL(response.config.url) &&
        'organization' in (response.data || {})
    ) {
        const newOrgId: number | null = response.data.organization;
        if (config.organization.organizationID !== newOrgId) {
            config?.onOrganizationChange(newOrgId);
        }
    }

    return response;
});

// Previously, we used to store an additional authentication token in local storage.
// Now we don't, and if the user still has one stored, we'll remove it to prevent
// unnecessary credential exposure.
store.remove('token');

function setAuthData(response: AxiosResponse): void {
    if (response.headers['set-cookie']) {
        // Browser itself setup cookie and header is none
        // In NodeJS we need do it manually
        const cookies = response.headers['set-cookie'].join(';');
        Axios.defaults.headers.common.Cookie = cookies;
    }
}

async function about(): Promise<SerializedAbout> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/server/about`);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function share(directoryArg: string, searchPrefix?: string): Promise<SerializedRemoteFile[]> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/server/share`, {
            params: {
                directory: directoryArg,
                ...(searchPrefix ? { search: searchPrefix } : {}),
            },
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function formats(): Promise<SerializedAnnotationFormats> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/server/annotation/formats`);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function userAgreements(): Promise<SerializedUserAgreement[]> {
    const { backendAPI } = config;
    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/user-agreements`, {
            validateStatus: (status) => status === 200 || status === 404,
        });

        if (response.status === 200) {
            return response.data;
        }

        return [];
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function register(
    username: string,
    firstName: string,
    lastName: string,
    email: string,
    password: string,
    confirmations: Record<string, string>,
): Promise<SerializedRegister> {
    let response = null;
    try {
        response = await Axios.post(`${config.backendAPI}/auth/register`, {
            username,
            first_name: firstName,
            last_name: lastName,
            email,
            password1: password,
            password2: password,
            confirmations,
        });
        setAuthData(response);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function login(credential: string, password: string): Promise<void> {
    let authenticationResponse = null;
    try {
        authenticationResponse = await Axios.post(`${config.backendAPI}/auth/login`, {
            [isEmail(credential) ? 'email' : 'username']: credential,
            password,
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    setAuthData(authenticationResponse);
}

async function logout(): Promise<void> {
    try {
        await Axios.post(`${config.backendAPI}/auth/logout`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function changePassword(oldPassword: string, newPassword1: string, newPassword2: string): Promise<void> {
    try {
        await Axios.post(`${config.backendAPI}/auth/password/change`, {
            old_password: oldPassword,
            new_password1: newPassword1,
            new_password2: newPassword2,
        });
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function requestPasswordReset(email: string): Promise<void> {
    try {
        await Axios.post(`${config.backendAPI}/auth/password/reset`, {
            email,
        });
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function resetPassword(newPassword1: string, newPassword2: string, uid: string, _token: string): Promise<void> {
    try {
        await Axios.post(`${config.backendAPI}/auth/password/reset/confirm`, {
            new_password1: newPassword1,
            new_password2: newPassword2,
            uid,
            token: _token,
        });
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function acceptOrganizationInvitation(
    key: string,
): Promise<string> {
    let response = null;
    let orgSlug = null;
    try {
        response = await Axios.post(`${config.backendAPI}/invitations/${key}/accept`);
        orgSlug = response.data.organization_slug;
    } catch (errorData) {
        throw generateError(errorData);
    }

    return orgSlug;
}

async function declineOrganizationInvitation(key: string): Promise<void> {
    try {
        await Axios.post(`${config.backendAPI}/invitations/${key}/decline`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getSelf(): Promise<SerializedUser> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/users/self`);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function authenticated(): Promise<boolean> {
    try {
        await getSelf();
    } catch (serverError) {
        if (serverError.code === 401) {
            return false;
        }

        throw serverError;
    }

    return true;
}

async function healthCheck(
    maxRetries: number,
    checkPeriod: number,
    requestTimeout: number,
    progressCallback?: (status: string) => void,
): Promise<void> {
    const { backendAPI } = config;
    const url = `${backendAPI}/server/health/?format=json`;

    const adjustedMaxRetries = Math.max(1, maxRetries);
    const adjustedCheckPeriod = Math.max(100, checkPeriod);
    const adjustedRequestTimeout = Math.max(500, requestTimeout);

    let lastError: AxiosError = null;
    for (let attempt = 1; attempt <= adjustedMaxRetries; attempt++) {
        if (progressCallback) {
            progressCallback(`${attempt}/${adjustedMaxRetries}`);
        }

        try {
            const response = await Axios.get(url, { timeout: adjustedRequestTimeout });
            return response.data;
        } catch (error) {
            lastError = error;
            if (attempt < adjustedMaxRetries) {
                await new Promise((resolve) => { setTimeout(resolve, adjustedCheckPeriod); });
            }
        }
    }

    throw generateError(lastError);
}

export interface ServerRequestConfig {
    fetchAll: boolean,
}

export const sleep = (time: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, time); });

const defaultRequestConfig = {
    fetchAll: false,
};

async function getRequestsList(): Promise<PaginatedResource<SerializedRequest>> {
    const { backendAPI } = config;
    const params = enableOrganization();

    try {
        const response = await fetchAll(`${backendAPI}/requests`, params);

        return response.results;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

// Temporary solution for server availability problems
const retryTimeouts = [5000, 10000, 15000];
async function getRequestStatus(rqID: string): Promise<SerializedRequest> {
    const { backendAPI } = config;
    let retryCount = 0;
    let lastError = null;

    while (retryCount < 3) {
        try {
            const response = await Axios.get(`${backendAPI}/requests/${rqID}`);

            return response.data;
        } catch (errorData) {
            lastError = generateError(errorData);
            const { response } = errorData;
            if (response && [502, 503, 504].includes(response.status)) {
                const timeout = retryTimeouts[retryCount];
                await new Promise((resolve) => { setTimeout(resolve, timeout); });
                retryCount++;
            } else {
                throw generateError(errorData);
            }
        }
    }

    throw lastError;
}

async function cancelRequest(requestID): Promise<void> {
    const { backendAPI } = config;

    try {
        await Axios.post(`${backendAPI}/requests/${requestID}/cancel`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function serverRequest(
    url: string, data: object,
    requestConfig: ServerRequestConfig = defaultRequestConfig,
): Promise<any> {
    try {
        let res = null;
        const { fetchAll: useFetchAll } = requestConfig;
        if (useFetchAll) {
            res = await fetchAll(url);
        } else {
            res = await Axios(url, data);
        }
        return res;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function searchProjectNames(search: string, limit: number): Promise<SerializedProject[] & { count: number }> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/projects`, {
            params: {
                names_only: true,
                page: 1,
                page_size: limit,
                search,
            },
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    response.data.results.count = response.data.count;
    return response.data.results;
}

async function getProjects(filter: ProjectsFilter = {}): Promise<SerializedProject[] & { count: number }> {
    const { backendAPI } = config;

    let response = null;
    try {
        if ('id' in filter) {
            response = await Axios.get(`${backendAPI}/projects/${filter.id}`);
            const results = [response.data];
            Object.defineProperty(results, 'count', {
                value: 1,
            });
            return results as SerializedProject[] & { count: number };
        }

        response = await Axios.get(`${backendAPI}/projects`, {
            params: {
                ...filter,
                page_size: 12,
            },
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    response.data.results.count = response.data.count;
    return response.data.results;
}

async function saveProject(id: number, projectData: Partial<SerializedProject>): Promise<SerializedProject> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.patch(`${backendAPI}/projects/${id}`, projectData);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function deleteProject(id: number): Promise<void> {
    const { backendAPI } = config;

    try {
        await Axios.delete(`${backendAPI}/projects/${id}`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function createProject(projectSpec: SerializedProject): Promise<SerializedProject> {
    const { backendAPI } = config;

    try {
        const response = await Axios.post(`${backendAPI}/projects`, projectSpec);
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getTasks(
    filter: TasksFilter = {},
    aggregate?: boolean,
): Promise<PaginatedResource<SerializedTask>> {
    const { backendAPI } = config;
    let response = null;
    try {
        if (aggregate) {
            response = {
                data: await fetchAll(`${backendAPI}/tasks`, {
                    ...filter,
                    ...enableOrganization(),
                }),
            };
        } else if ('id' in filter) {
            response = await Axios.get(`${backendAPI}/tasks/${filter.id}`);
            const results = [response.data];
            Object.defineProperty(results, 'count', {
                value: 1,
            });

            return results as PaginatedResource<SerializedTask>;
        } else {
            response = await Axios.get(`${backendAPI}/tasks`, {
                params: {
                    ...filter,
                    page_size: filter.page_size ?? 10,
                },
            });
        }
    } catch (errorData) {
        throw generateError(errorData);
    }

    response.data.results.count = response.data.count;
    return response.data.results;
}

async function saveTask(id: number, taskData: Partial<SerializedTask>): Promise<SerializedTask> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.patch(`${backendAPI}/tasks/${id}`, taskData);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function deleteTask(id: number, organizationID: string | null = null): Promise<void> {
    const { backendAPI } = config;

    try {
        await Axios.delete(`${backendAPI}/tasks/${id}`, {
            params: {
                ...(organizationID ? { org: organizationID } : {}),
            },
        });
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function mergeConsensusJobs(id: number, instanceType: string): Promise<string> {
    const { backendAPI } = config;
    const url = `${backendAPI}/consensus/merges`;
    const requestBody = (instanceType === 'task') ? { task_id: id } : { job_id: id };

    return new Promise<string>((resolve, reject) => {
        async function request() {
            try {
                const response = await Axios.post(url, requestBody);
                const rqID = response.data.rq_id;
                const { status } = response;
                if (status === 202) {
                    resolve(rqID);
                } else {
                    reject(generateError(response));
                }
            } catch (errorData) {
                reject(generateError(errorData));
            }
        }
        setTimeout(request);
    });
}

async function getLabels(filter: {
    job_id?: number,
    task_id?: number,
    project_id?: number,
}): Promise<{ results: SerializedLabel[] }> {
    const { backendAPI } = config;
    return fetchAll(`${backendAPI}/labels`, {
        ...filter,
        ...enableOrganization(),
    });
}

async function deleteLabel(id: number): Promise<void> {
    const { backendAPI } = config;
    try {
        await Axios.delete(`${backendAPI}/labels/${id}`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function updateLabel(id: number, body: SerializedLabel): Promise<SerializedLabel> {
    const { backendAPI } = config;
    let response = null;
    try {
        response = await Axios.patch(`${backendAPI}/labels/${id}`, body);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

function exportDataset(instanceType: 'projects' | 'jobs' | 'tasks') {
    return async function (
        id: number,
        format: string,
        saveImages: boolean,
        useDefaultSettings: boolean,
        targetStorage: Storage,
        name?: string,
    ) {
        const { backendAPI } = config;
        const baseURL = `${backendAPI}/${instanceType}/${id}/dataset/export`;
        const params: Params = {
            ...enableOrganization(),
            ...configureStorage(targetStorage, useDefaultSettings),
            ...(name ? { filename: name } : {}),
            format,
            save_images: saveImages,
        };
        return new Promise<string | void>((resolve, reject) => {
            async function request() {
                Axios.post(baseURL, {}, {
                    params,
                })
                    .then((response) => {
                        if (response.status === 202) {
                            resolve(response.data.rq_id);
                        }
                        resolve();
                    })
                    .catch((errorData) => {
                        reject(generateError(errorData));
                    });
            }

            setTimeout(request);
        });
    };
}

async function importDataset(
    id: number,
    format: string,
    useDefaultLocation: boolean,
    sourceStorage: Storage,
    file: File | string,
    options: {
        convMaskToPoly: boolean,
        updateStatusCallback: (message: string, progress: number) => void,
    },
): Promise<string> {
    const { backendAPI, origin } = config;
    const params: Params & { conv_mask_to_poly: boolean } = {
        ...enableOrganization(),
        ...configureStorage(sourceStorage, useDefaultLocation),
        format,
        filename: typeof file === 'string' ? file : file.name,
        conv_mask_to_poly: options.convMaskToPoly,
    };

    const url = `${backendAPI}/projects/${id}/dataset`;
    const isCloudStorage = sourceStorage.location === StorageLocation.CLOUD_STORAGE;

    try {
        if (isCloudStorage) {
            const response = await Axios.post(url,
                new FormData(),
                {
                    params,
                });
            return response.data.rq_id;
        }
        const uploadConfig = {
            chunkSize: config.uploadChunkSize * 1024 * 1024,
            endpoint: `${origin}${backendAPI}/projects/${id}/dataset/`,
            totalSentSize: 0,
            totalSize: (file as File).size,
            onUpdate: (percentage) => {
                options.updateStatusCallback('The dataset is being uploaded to the server', percentage);
            },
        };
        await Axios.post(url,
            new FormData(),
            {
                params,
                headers: { 'Upload-Start': true },
            });
        const { filename } = await chunkUpload(file as File, uploadConfig);
        const response = await Axios.post(url,
            new FormData(),
            {
                params: { ...params, filename },
                headers: { 'Upload-Finish': true },
            });
        return response.data.rq_id;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function backupTask(
    id: number,
    targetStorage: Storage,
    useDefaultSettings: boolean,
    fileName?: string,
): Promise<string | void> {
    const { backendAPI } = config;
    const params: Params = {
        ...enableOrganization(),
        ...configureStorage(targetStorage, useDefaultSettings),
        ...(fileName ? { filename: fileName } : {}),
    };
    const url = `${backendAPI}/tasks/${id}/backup/export`;

    return new Promise<string | void>((resolve, reject) => {
        async function request() {
            try {
                const response = await Axios.post(url, {}, {
                    params,
                });
                if (response.status === 202) {
                    resolve(response.data.rq_id);
                }
                resolve();
            } catch (errorData) {
                reject(generateError(errorData));
            }
        }

        setTimeout(request);
    });
}

async function restoreTask(storage: Storage, file: File | string): Promise<string> {
    const { backendAPI } = config;
    // keep current default params to 'freeze" them during this request
    const params: Params = {
        ...enableOrganization(),
        ...configureStorage(storage),
    };

    const url = `${backendAPI}/tasks/backup`;
    const isCloudStorage = storage.location === StorageLocation.CLOUD_STORAGE;
    let response;

    try {
        if (isCloudStorage) {
            params.filename = file as string;
            response = await Axios.post(url,
                new FormData(),
                {
                    params,
                });
            return response.data.rq_id;
        }
        const uploadConfig = {
            chunkSize: config.uploadChunkSize * 1024 * 1024,
            endpoint: `${origin}${backendAPI}/tasks/backup/`,
            totalSentSize: 0,
            totalSize: (file as File).size,
        };
        await Axios.post(url,
            new FormData(),
            {
                params,
                headers: { 'Upload-Start': true },
            });
        const { filename } = await chunkUpload(file as File, uploadConfig);
        response = await Axios.post(url,
            new FormData(),
            {
                params: { ...params, filename },
                headers: { 'Upload-Finish': true },
            });
        return response.data.rq_id;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function backupProject(
    id: number,
    targetStorage: Storage,
    useDefaultSettings: boolean,
    fileName?: string,
): Promise<string | void> {
    const { backendAPI } = config;
    // keep current default params to 'freeze" them during this request
    const params: Params = {
        ...enableOrganization(),
        ...configureStorage(targetStorage, useDefaultSettings),
        ...(fileName ? { filename: fileName } : {}),
    };

    const url = `${backendAPI}/projects/${id}/backup/export`;

    return new Promise<string | void>((resolve, reject) => {
        async function request() {
            try {
                const response = await Axios.post(url, {}, {
                    params,
                });
                if (response.status === 202) {
                    resolve(response.data.rq_id);
                }
                resolve();
            } catch (errorData) {
                reject(generateError(errorData));
            }
        }

        setTimeout(request);
    });
}

async function restoreProject(storage: Storage, file: File | string): Promise<string> {
    const { backendAPI } = config;
    // keep current default params to 'freeze" them during this request
    const params: Params = {
        ...enableOrganization(),
        ...configureStorage(storage),
    };

    const url = `${backendAPI}/projects/backup`;
    const isCloudStorage = storage.location === StorageLocation.CLOUD_STORAGE;
    let response;

    try {
        if (isCloudStorage) {
            params.filename = file;
            response = await Axios.post(url,
                new FormData(),
                {
                    params,
                });
            return response.data.rq_id;
        }
        const uploadConfig = {
            chunkSize: config.uploadChunkSize * 1024 * 1024,
            endpoint: `${origin}${backendAPI}/projects/backup/`,
            totalSentSize: 0,
            totalSize: (file as File).size,
        };
        await Axios.post(url,
            new FormData(),
            {
                params,
                headers: { 'Upload-Start': true },
            });
        const { filename } = await chunkUpload(file as File, uploadConfig);
        response = await Axios.post(url,
            new FormData(),
            {
                params: { ...params, filename },
                headers: { 'Upload-Finish': true },
            });
        return response.data.rq_id;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function createTask(
    taskSpec: Partial<SerializedTask>,
    taskDataSpec: any,
    onUpdate: (request: Request | UpdateStatusData) => void,
): Promise<{ taskID: number, rqID: string }> {
    const { backendAPI, origin } = config;
    // keep current default params to 'freeze" them during this request
    const params = enableOrganization();

    const chunkSize = config.uploadChunkSize * 1024 * 1024;
    const clientFiles = taskDataSpec.client_files;
    const chunkFiles = [];
    const bulkFiles = [];
    let totalSize = 0;
    let totalSentSize = 0;
    for (const file of clientFiles) {
        if (file.size > chunkSize) {
            chunkFiles.push(file);
        } else {
            bulkFiles.push(file);
        }
        totalSize += file.size;
    }
    delete taskDataSpec.client_files;

    const taskData = new FormData();
    for (const [key, value] of Object.entries(taskDataSpec)) {
        if (Array.isArray(value)) {
            value.forEach((element, idx) => {
                taskData.append(`${key}[${idx}]`, element);
            });
        } else if (typeof value !== 'object') {
            taskData.set(key, value);
        }
    }

    let response = null;

    onUpdate({
        status: RQStatus.UNKNOWN,
        progress: 0,
        message: 'CVAT is creating your task',
    });

    try {
        response = await Axios.post(`${backendAPI}/tasks`, taskSpec, {
            params,
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    onUpdate({
        status: RQStatus.UNKNOWN,
        progress: 0,
        message: 'CVAT is uploading task data to the server',
    });

    async function bulkUpload(taskId, files) {
        const fileBulks = files.reduce((fileGroups, file) => {
            const lastBulk = fileGroups[fileGroups.length - 1];
            if (chunkSize - lastBulk.size >= file.size) {
                lastBulk.files.push(file);
                lastBulk.size += file.size;
            } else {
                fileGroups.push({ files: [file], size: file.size });
            }
            return fileGroups;
        }, [{ files: [], size: 0 }]);
        const totalBulks = fileBulks.length;
        let currentChunkNumber = 0;
        while (currentChunkNumber < totalBulks) {
            for (const [idx, element] of fileBulks[currentChunkNumber].files.entries()) {
                taskData.append(`client_files[${idx}]`, element);
            }
            const percentage = totalSentSize / totalSize;
            onUpdate({
                status: RQStatus.UNKNOWN,
                progress: percentage,
                message: 'CVAT is uploading task data to the server',
            });
            await Axios.post(`${backendAPI}/tasks/${taskId}/data`, taskData, {
                ...params,
                headers: { 'Upload-Multiple': true },
            });
            for (let i = 0; i < fileBulks[currentChunkNumber].files.length; i++) {
                taskData.delete(`client_files[${i}]`);
            }
            totalSentSize += fileBulks[currentChunkNumber].size;
            currentChunkNumber++;
        }
    }

    let rqID = null;
    try {
        await Axios.post(`${backendAPI}/tasks/${response.data.id}/data`,
            {},
            {
                ...params,
                headers: { 'Upload-Start': true },
            });
        const uploadConfig = {
            endpoint: `${origin}${backendAPI}/tasks/${response.data.id}/data/`,
            onUpdate: (percentage) => {
                onUpdate({
                    status: RQStatus.UNKNOWN,
                    progress: percentage,
                    message: 'CVAT is uploading task data to the server',
                });
            },
            chunkSize,
            totalSize,
            totalSentSize,
        };
        for (const file of chunkFiles) {
            const { uploadSentSize } = await chunkUpload(file, uploadConfig);
            uploadConfig.totalSentSize += uploadSentSize;
        }
        if (bulkFiles.length > 0) {
            await bulkUpload(response.data.id, bulkFiles);
        }
        const dataResponse = await Axios.post(`${backendAPI}/tasks/${response.data.id}/data`,
            taskDataSpec,
            {
                ...params,
                headers: { 'Upload-Finish': true },
            });
        rqID = dataResponse.data.rq_id;
    } catch (errorData) {
        try {
            await deleteTask(response.data.id, params.org || null);
        } catch (_) {
            // ignore
        }
        throw generateError(errorData);
    }

    return { taskID: response.data.id, rqID };
}

async function getJobs(
    filter: JobsFilter = {},
    aggregate = false,
): Promise<SerializedJob[] & { count: number }> {
    const { backendAPI } = config;
    const id = filter.id || null;

    let response = null;
    try {
        if (id !== null) {
            response = await Axios.get(`${backendAPI}/jobs/${id}`);
            return Object.assign([response.data], { count: 1 });
        }

        if (aggregate) {
            response = {
                data: await fetchAll(`${backendAPI}/jobs`, {
                    ...filter,
                    ...enableOrganization(),
                }),
            };
        } else {
            response = await Axios.get(`${backendAPI}/jobs`, {
                params: {
                    ...filter,
                    page_size: 12,
                },
            });
        }
    } catch (errorData) {
        throw generateError(errorData);
    }

    response.data.results.count = response.data.count;
    return response.data.results;
}

async function getIssues(filter) {
    const { backendAPI } = config;

    let response = null;
    try {
        const organization = enableOrganization();
        response = await fetchAll(`${backendAPI}/issues`, {
            ...filter,
            ...organization,
        });

        if (filter.job_id) {
            const commentsResponse = await fetchAll(`${backendAPI}/comments`, {
                ...filter,
                ...organization,
            });

            const issuesById = response.results.reduce((acc, val: { id: number }) => {
                acc[val.id] = val;
                return acc;
            }, {});

            const commentsByIssue = commentsResponse.results.reduce((acc, val) => {
                acc[val.issue] = acc[val.issue] || [];
                acc[val.issue].push(val);
                return acc;
            }, {});

            for (const issue of Object.keys(commentsByIssue)) {
                commentsByIssue[issue].sort((a, b) => a.id - b.id);
                issuesById[issue].comments = commentsByIssue[issue];
            }
        }
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.results;
}

async function createComment(data) {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.post(`${backendAPI}/comments`, data);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function createIssue(data) {
    const { backendAPI } = config;

    let response = null;
    try {
        const organization = enableOrganization();
        response = await Axios.post(`${backendAPI}/issues`, data, {
            params: { ...organization },
        });

        const commentsResponse = await fetchAll(`${backendAPI}/comments`, {
            issue_id: response.data.id,
            ...organization,
        });

        response.data.comments = commentsResponse.results;
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function updateIssue(issueID, data) {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.patch(`${backendAPI}/issues/${issueID}`, data);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function deleteIssue(issueID: number): Promise<void> {
    const { backendAPI } = config;

    try {
        await Axios.delete(`${backendAPI}/issues/${issueID}`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function saveJob(id: number, jobData: Partial<SerializedJob>): Promise<SerializedJob> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.patch(`${backendAPI}/jobs/${id}`, jobData);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function createJob(jobData: Partial<SerializedJob>): Promise<SerializedJob> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.post(`${backendAPI}/jobs`, jobData);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function deleteJob(jobID: number): Promise<void> {
    const { backendAPI } = config;

    try {
        await Axios.delete(`${backendAPI}/jobs/${jobID}`, {
            params: {
                ...enableOrganization(),
            },
        });
    } catch (errorData) {
        throw generateError(errorData);
    }
}

const validationLayout = (instance: 'tasks' | 'jobs') => async (
    id: number,
): Promise<SerializedJobValidationLayout | SerializedTaskValidationLayout> => {
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/${instance}/${id}/validation_layout`, {
            params: {
                ...enableOrganization(),
            },
        });

        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
};

async function getUsers(filter = { page_size: 'all' }): Promise<SerializedUser[]> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/users`, {
            params: {
                ...filter,
            },
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data.results;
}

function getPreview(instance: 'projects' | 'tasks' | 'jobs' | 'cloudstorages' | 'functions') {
    return async function (id: number | string): Promise<Blob | null> {
        const { backendAPI } = config;

        let response = null;
        try {
            const url = `${backendAPI}/${instance}/${id}/preview`;
            response = await Axios.get(url, {
                responseType: 'blob',
            });

            return response.data;
        } catch (errorData) {
            const code = errorData.response ? errorData.response.status : errorData.code;
            if (code === 404) {
                return null;
            }
            throw new ServerError(`Could not get preview for "${instance}/${id}"`, code);
        }
    };
}

async function getImageContext(jid: number, frame: number): Promise<ArrayBuffer> {
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/jobs/${jid}/data`, {
            params: {
                quality: 'original',
                type: 'context_image',
                number: frame,
            },
            responseType: 'arraybuffer',
        });

        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getData(jid: number, chunk: number, quality: ChunkQuality, retry = 0): Promise<ArrayBuffer> {
    const { backendAPI } = config;

    try {
        const response = await (workerAxios as any).get(`${backendAPI}/jobs/${jid}/data`, {
            params: {
                ...enableOrganization(),
                quality,
                type: 'chunk',
                index: chunk,
            },
            responseType: 'arraybuffer',
        });

        const contentLength = +(response.headers || {})['content-length'];
        if (Number.isInteger(contentLength) && response.data.byteLength < +contentLength) {
            if (retry < 10) {
                // corrupted zip tmp workaround
                // if content length more than received byteLength, request the chunk again
                // and log this error
                setTimeout(() => {
                    throw new Error(
                        `Truncated chunk, try: ${retry}. Job: ${jid}, chunk: ${chunk}, quality: ${quality}. ` +
                        `Body size: ${response.data.byteLength}`,
                    );
                });
                return await getData(jid, chunk, quality, retry + 1);
            }

            // not to try anymore, throw explicit error
            throw new Error(
                `Truncated chunk. Job: ${jid}, chunk: ${chunk}, quality: ${quality}. ` +
                `Body size: ${response.data.byteLength}`,
            );
        }

        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getMeta(session: 'job' | 'task', id: number): Promise<SerializedFramesMetaData> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/${session}s/${id}/data/meta`);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function saveMeta(
    session: 'job' | 'task',
    id: number,
    meta: Partial<SerializedFramesMetaData>,
): Promise<SerializedFramesMetaData> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.patch(`${backendAPI}/${session}s/${id}/data/meta`, meta);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function getAnnotations(
    session: 'task' | 'job',
    id: number,
): Promise<SerializedCollection> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/${session}s/${id}/annotations`);
    } catch (errorData) {
        throw generateError(errorData);
    }
    return response.data;
}

async function updateAnnotations(
    session: 'task' | 'job',
    id: number,
    data: SerializedCollection,
    action: 'create' | 'update' | 'delete' | 'put',
): Promise<SerializedCollection> {
    const { backendAPI } = config;
    const url = `${backendAPI}/${session}s/${id}/annotations`;
    const params: Record<string, string> = {};
    let method: string;

    if (action.toUpperCase() === 'PUT') {
        method = 'PUT';
    } else {
        method = 'PATCH';
        params.action = action;
    }

    let response = null;
    try {
        response = await Axios(url, { method, data, params });
    } catch (errorData) {
        throw generateError(errorData);
    }
    return response.data;
}

// Session is 'task' or 'job'
async function uploadAnnotations(
    session,
    id: number,
    format: string,
    useDefaultLocation: boolean,
    sourceStorage: Storage,
    file: File | string,
    options: { convMaskToPoly: boolean },
): Promise<string> {
    const { backendAPI, origin } = config;
    const params: Params & { conv_mask_to_poly: boolean } = {
        ...enableOrganization(),
        ...configureStorage(sourceStorage, useDefaultLocation),
        format,
        filename: typeof file === 'string' ? file : file.name,
        conv_mask_to_poly: options.convMaskToPoly,
    };

    const url = `${backendAPI}/${session}s/${id}/annotations`;
    const isCloudStorage = sourceStorage.location === StorageLocation.CLOUD_STORAGE;

    try {
        if (isCloudStorage) {
            const response = await Axios.post(url,
                new FormData(),
                {
                    params,
                });
            return response.data.rq_id;
        }
        const chunkSize = config.uploadChunkSize * 1024 * 1024;
        const uploadConfig = {
            chunkSize,
            endpoint: `${origin}${backendAPI}/${session}s/${id}/annotations/`,
        };
        await Axios.post(url,
            new FormData(),
            {
                params,
                headers: { 'Upload-Start': true },
            });
        const { filename } = await chunkUpload(file as File, uploadConfig);
        const response = await Axios.post(url,
            new FormData(),
            {
                params: { ...params, filename },
                headers: { 'Upload-Finish': true },
            });
        return response.data.rq_id;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function saveEvents(events: {
    events: SerializedEvent[];
    previous_event?: SerializedEvent;
    timestamp: string;
}): Promise<void> {
    const { backendAPI } = config;

    try {
        await Axios.post(`${backendAPI}/events`, events);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

const eventsExportRequests: Record<string, { promise: Promise<string> }> = {};
function exportEvents(params: APIAnalyticsEventsFilter): Promise<string> {
    const { backendAPI } = config;
    const key = JSON.stringify(params, Object.keys(params).sort());
    const existingRequest = eventsExportRequests[key];

    if (existingRequest) {
        return existingRequest.promise;
    }

    const promise = new Promise<string>((resolve, reject) => {
        Axios.get(`${backendAPI}/events`, { params }).then((response) => {
            const paramsWithQuery = {
                ...params,
                query_id: response.data.query_id,
            };

            const checkCallback = () => {
                Axios.get(`${backendAPI}/events`, { params: paramsWithQuery }).then((checkResponse) => {
                    if (checkResponse.status === 202) {
                        setTimeout(checkCallback, 10000);
                    } else if (checkResponse.status === 201) {
                        const paramsObject = new URLSearchParams(paramsWithQuery as any);
                        paramsObject.set('action', 'download');
                        resolve(`${backendAPI}/events?${paramsObject.toString()}`);
                    } else {
                        reject(new Error(`Unexpected API code received: ${checkResponse.status}`));
                    }
                }).catch((error: unknown) => {
                    reject(error);
                });
            };

            setTimeout(checkCallback, 2000);
        }).catch((error: unknown) => {
            reject(error);
        });
    });

    eventsExportRequests[key] = { promise };
    promise.finally(() => {
        delete eventsExportRequests[key];
    });

    return promise;
}

async function getLambdaFunctions() {
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/lambda/functions`);
        return response.data;
    } catch (errorData) {
        if (errorData.response.status === 503) {
            return [];
        }
        throw generateError(errorData);
    }
}

async function runLambdaRequest(body) {
    const { backendAPI } = config;

    try {
        const response = await Axios.post(`${backendAPI}/lambda/requests`, body);

        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function callLambdaFunction(funId, body) {
    const { backendAPI } = config;

    try {
        const response = await Axios.post(`${backendAPI}/lambda/functions/${funId}`, body);

        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getLambdaRequests() {
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/lambda/requests`);
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getLambdaRequestStatus(requestID) {
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/lambda/requests/${requestID}`);
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function cancelLambdaRequest(requestId) {
    const { backendAPI } = config;

    try {
        await Axios.delete(`${backendAPI}/lambda/requests/${requestId}`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function installedApps() {
    const { backendAPI } = config;
    try {
        const response = await Axios.get(`${backendAPI}/server/plugins`);
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getApiSchema(): Promise<SerializedAPISchema> {
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/schema/?scheme=json`);
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function createCloudStorage(storageDetail) {
    const { backendAPI } = config;

    const storageDetailData = prepareData(storageDetail);
    try {
        const response = await Axios.post(`${backendAPI}/cloudstorages`, storageDetailData);
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function updateCloudStorage(id, storageDetail) {
    const { backendAPI } = config;

    const storageDetailData = prepareData(storageDetail);
    try {
        await Axios.patch(`${backendAPI}/cloudstorages/${id}`, storageDetailData);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getCloudStorages(filter = {}): Promise<SerializedCloudStorage[] & { count: number }> {
    const { backendAPI } = config;

    let response = null;
    try {
        if ('id' in filter) {
            response = await Axios.get(`${backendAPI}/cloudstorages/${filter.id}`);
            return Object.assign([response.data], { count: 1 });
        }

        response = await Axios.get(`${backendAPI}/cloudstorages`, {
            params: {
                ...filter,
                page_size: 12,
            },
        });
        return Object.assign(response.data.results, { count: response.data.count });
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getCloudStorageContent(id: number, path: string, nextToken?: string, manifestPath?: string):
Promise<{ content: SerializedRemoteFile[], next: string | null }> {
    const { backendAPI } = config;

    let response = null;
    try {
        const url = `${backendAPI}/cloudstorages/${id}/content-v2`;
        response = await Axios.get(url, {
            params: {
                prefix: path,
                ...(nextToken ? { next_token: nextToken } : {}),
                ...(manifestPath ? { manifest_path: manifestPath } : {}),
            },
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function getCloudStorageStatus(id) {
    const { backendAPI } = config;

    let response = null;
    try {
        const url = `${backendAPI}/cloudstorages/${id}/status`;
        response = await Axios.get(url);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function deleteCloudStorage(id) {
    const { backendAPI } = config;

    try {
        await Axios.delete(`${backendAPI}/cloudstorages/${id}`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getOrganizations(filter) {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/organizations`, {
            params: {
                ...filter,
            },
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data.results;
}

async function createOrganization(data: SerializedOrganization): Promise<SerializedOrganization> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.post(`${backendAPI}/organizations`, data, {
            params: { org: '' },
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function updateOrganization(
    id: number, data: Partial<SerializedOrganization>,
): Promise<SerializedOrganization> {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.patch(`${backendAPI}/organizations/${id}`, data);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function deleteOrganization(id: number): Promise<void> {
    const { backendAPI } = config;

    try {
        await Axios.delete(`${backendAPI}/organizations/${id}`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getOrganizationMembers(params = {}) {
    const { backendAPI } = config;

    let response = null;
    try {
        response = await Axios.get(`${backendAPI}/memberships`, {
            params,
        });
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function inviteOrganizationMembers(orgId, data) {
    const { backendAPI } = config;
    try {
        await Axios.post(
            `${backendAPI}/invitations`,
            {
                ...data,
                organization: orgId,
            },
        );
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function resendOrganizationInvitation(key) {
    const { backendAPI } = config;
    try {
        await Axios.post(`${backendAPI}/invitations/${key}/resend`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function updateOrganizationMembership(membershipId, data) {
    const { backendAPI } = config;
    let response = null;
    try {
        response = await Axios.patch(`${backendAPI}/memberships/${membershipId}`, data);
    } catch (errorData) {
        throw generateError(errorData);
    }

    return response.data;
}

async function deleteOrganizationMembership(membershipId: number): Promise<void> {
    const { backendAPI } = config;

    try {
        await Axios.delete(`${backendAPI}/memberships/${membershipId}`);
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getMembershipInvitations(
    filter: { page?: number, filter?: string, key?: string },
): Promise<{ results: SerializedInvitationData[], count: number }> {
    const { backendAPI } = config;

    let response = null;
    try {
        const key = filter.key || null;

        if (key) {
            response = await Axios.get(`${backendAPI}/invitations/${key}`);
            return ({
                results: [response.data],
                count: 1,
            });
        }

        response = await Axios.get(`${backendAPI}/invitations`, {
            params: {
                ...filter,
                page_size: 11,
            },
        });
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getWebhookDelivery(webhookID: number, deliveryID: number): Promise<any> {
    const params = enableOrganization();
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/webhooks/${webhookID}/deliveries/${deliveryID}`, {
            params,
        });
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getWebhooks(filter, pageSize = 10): Promise<any> {
    const params = enableOrganization();
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/webhooks`, {
            params: {
                ...params,
                ...filter,
                page_size: pageSize,
            },
        });

        response.data.results.count = response.data.count;
        return response.data.results;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function createWebhook(webhookData: any): Promise<any> {
    const params = enableOrganization();
    const { backendAPI } = config;

    try {
        const response = await Axios.post(`${backendAPI}/webhooks`, webhookData, {
            params,
        });
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function updateWebhook(webhookID: number, webhookData: any): Promise<any> {
    const params = enableOrganization();
    const { backendAPI } = config;

    try {
        const response = await Axios.patch(`${backendAPI}/webhooks/${webhookID}`, webhookData, {
            params,
        });
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function deleteWebhook(webhookID: number): Promise<void> {
    const params = enableOrganization();
    const { backendAPI } = config;

    try {
        await Axios.delete(`${backendAPI}/webhooks/${webhookID}`, {
            params,
        });
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function pingWebhook(webhookID: number): Promise<any> {
    const params = enableOrganization();
    const { backendAPI } = config;

    async function waitPingDelivery(deliveryID: number): Promise<any> {
        return new Promise((resolve) => {
            async function checkStatus(): Promise<any> {
                const delivery = await getWebhookDelivery(webhookID, deliveryID);
                if (delivery.status_code) {
                    resolve(delivery);
                } else {
                    setTimeout(checkStatus, 1000);
                }
            }
            setTimeout(checkStatus, 1000);
        });
    }

    try {
        const response = await Axios.post(`${backendAPI}/webhooks/${webhookID}/ping`, {
            params,
        });

        const deliveryID = response.data.id;
        const delivery = await waitPingDelivery(deliveryID);
        return delivery;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function receiveWebhookEvents(type: WebhookSourceType): Promise<string[]> {
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/webhooks/events`, {
            params: {
                type,
            },
        });
        return response.data.events;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getGuide(id: number): Promise<SerializedGuide> {
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/guides/${id}`);
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function createGuide(data: Partial<SerializedGuide>): Promise<SerializedGuide> {
    const { backendAPI } = config;

    try {
        const response = await Axios.post(`${backendAPI}/guides`, data);
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function updateGuide(id: number, data: Partial<SerializedGuide>): Promise<SerializedGuide> {
    const { backendAPI } = config;

    try {
        const response = await Axios.patch(`${backendAPI}/guides/${id}`, data);
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function createAsset(file: File, guideId: number): Promise<SerializedAsset> {
    const { backendAPI } = config;
    const form = new FormData();
    form.append('file', file);
    form.append('guide_id', guideId);

    try {
        const response = await Axios.post(`${backendAPI}/assets`, form, {
            headers: {
                'Content-Type': 'multipart/form-data',
            },
        });
        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getQualitySettings(
    filter: APIQualitySettingsFilter,
    aggregate?: boolean,
): Promise<PaginatedResource<SerializedQualitySettingsData>> {
    const { backendAPI } = config;

    let response = null;
    try {
        if (aggregate) {
            response = {
                data: await fetchAll(`${backendAPI}/quality/settings`, {
                    ...filter,
                    ...enableOrganization(),
                }),
            };
        } else {
            response = await Axios.get(`${backendAPI}/quality/settings`, {
                params: {
                    ...filter,
                },
            });
        }
    } catch (errorData) {
        throw generateError(errorData);
    }

    response.data.results.count = response.data.count;
    return response.data.results;
}

async function updateQualitySettings(
    settingsID: number,
    settingsData: SerializedQualitySettingsData,
): Promise<SerializedQualitySettingsData> {
    const params = enableOrganization();
    const { backendAPI } = config;

    try {
        const response = await Axios.patch(`${backendAPI}/quality/settings/${settingsID}`, settingsData, {
            params,
        });

        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getConsensusSettings(
    filter: APIConsensusSettingsFilter,
): Promise<SerializedConsensusSettingsData> {
    const { backendAPI } = config;

    try {
        const response = await Axios.get(`${backendAPI}/consensus/settings`, {
            params: {
                ...filter,
            },
        });

        return response.data.results[0];
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function updateConsensusSettings(
    settingsID: number,
    settingsData: SerializedConsensusSettingsData,
): Promise<SerializedConsensusSettingsData> {
    const params = enableOrganization();
    const { backendAPI } = config;

    try {
        const response = await Axios.patch(`${backendAPI}/consensus/settings/${settingsID}`, settingsData, {
            params,
        });

        return response.data;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getQualityConflicts(
    filter: APIQualityConflictsFilter,
): Promise<SerializedQualityConflictData[]> {
    const params = enableOrganization();
    const { backendAPI } = config;

    try {
        const response = await fetchAll(`${backendAPI}/quality/conflicts`, {
            ...params,
            ...filter,
        });

        return response.results;
    } catch (errorData) {
        throw generateError(errorData);
    }
}

async function getQualityReports(
    filter: APIQualityReportsFilter,
    aggregate?: boolean,
): Promise<PaginatedResource<SerializedQualityReportData>> {
    const { backendAPI } = config;

    let response = null;
    try {
        if (aggregate) {
            response = {
                data: await fetchAll(`${backendAPI}/quality/reports`, {
                    ...filter,
                    ...enableOrganization(),
                }),
            };
        } else {
            response = await Axios.get(`${backendAPI}/quality/reports`, {
                params: {
                    ...filter,
                },
            });
        }
    } catch (errorData) {
        throw generateError(errorData);
    }

    response.data.results.count = response.data.count;
    return response.data.results;
}

export default Object.freeze({
    server: Object.freeze({
        setAuthData,
        about,
        share,
        formats,
        login,
        logout,
        changePassword,
        requestPasswordReset,
        resetPassword,
        authenticated,
        healthCheck,
        register,
        request: serverRequest,
        userAgreements,
        installedApps,
        apiSchema: getApiSchema,
    }),

    projects: Object.freeze({
        get: getProjects,
        searchNames: searchProjectNames,
        save: saveProject,
        create: createProject,
        delete: deleteProject,
        exportDataset: exportDataset('projects'),
        getPreview: getPreview('projects'),
        backup: backupProject,
        restore: restoreProject,
        importDataset,
    }),

    tasks: Object.freeze({
        get: getTasks,
        save: saveTask,
        create: createTask,
        delete: deleteTask,
        exportDataset: exportDataset('tasks'),
        getPreview: getPreview('tasks'),
        backup: backupTask,
        restore: restoreTask,
        validationLayout: validationLayout('tasks'),
        mergeConsensusJobs,
    }),

    labels: Object.freeze({
        get: getLabels,
        delete: deleteLabel,
        update: updateLabel,
    }),

    jobs: Object.freeze({
        get: getJobs,
        getPreview: getPreview('jobs'),
        save: saveJob,
        create: createJob,
        delete: deleteJob,
        exportDataset: exportDataset('jobs'),
        validationLayout: validationLayout('jobs'),
        mergeConsensusJobs,
    }),

    users: Object.freeze({
        get: getUsers,
        self: getSelf,
    }),

    frames: Object.freeze({
        getData,
        getMeta,
        saveMeta,
        getPreview,
        getImageContext,
    }),

    annotations: Object.freeze({
        updateAnnotations,
        getAnnotations,
        uploadAnnotations,
    }),

    events: Object.freeze({
        save: saveEvents,
        export: exportEvents,
    }),

    lambda: Object.freeze({
        list: getLambdaFunctions,
        status: getLambdaRequestStatus,
        requests: getLambdaRequests,
        run: runLambdaRequest,
        call: callLambdaFunction,
        cancel: cancelLambdaRequest,
    }),

    issues: Object.freeze({
        create: createIssue,
        update: updateIssue,
        get: getIssues,
        delete: deleteIssue,
    }),

    comments: Object.freeze({
        create: createComment,
    }),

    cloudStorages: Object.freeze({
        get: getCloudStorages,
        getContent: getCloudStorageContent,
        getPreview: getPreview('cloudstorages'),
        getStatus: getCloudStorageStatus,
        create: createCloudStorage,
        delete: deleteCloudStorage,
        update: updateCloudStorage,
    }),

    organizations: Object.freeze({
        get: getOrganizations,
        create: createOrganization,
        update: updateOrganization,
        members: getOrganizationMembers,
        invitations: getMembershipInvitations,
        delete: deleteOrganization,
        invite: inviteOrganizationMembers,
        resendInvitation: resendOrganizationInvitation,
        updateMembership: updateOrganizationMembership,
        deleteMembership: deleteOrganizationMembership,
        acceptInvitation: acceptOrganizationInvitation,
        declineInvitation: declineOrganizationInvitation,
    }),

    webhooks: Object.freeze({
        get: getWebhooks,
        create: createWebhook,
        update: updateWebhook,
        delete: deleteWebhook,
        ping: pingWebhook,
        events: receiveWebhookEvents,
    }),

    guides: Object.freeze({
        get: getGuide,
        create: createGuide,
        update: updateGuide,
    }),

    assets: Object.freeze({
        create: createAsset,
    }),

    analytics: Object.freeze({
        quality: Object.freeze({
            reports: getQualityReports,
            conflicts: getQualityConflicts,
            settings: Object.freeze({
                get: getQualitySettings,
                update: updateQualitySettings,
            }),
        }),
    }),

    consensus: Object.freeze({
        settings: Object.freeze({
            get: getConsensusSettings,
            update: updateConsensusSettings,
        }),
    }),

    requests: Object.freeze({
        list: getRequestsList,
        status: getRequestStatus,
        cancel: cancelRequest,
    }),
});
