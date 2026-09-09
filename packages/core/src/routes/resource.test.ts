import {
  type Resource,
  type CreateResource,
  getManagementApiResourceIndicator,
} from '@logto/schemas';
import { pickDefault } from '@logto/shared/esm';
import { type Nullable } from '@silverhand/essentials';

import { mockResource, mockScope } from '#src/__mocks__/index.js';
import { mockId, mockIdGenerators } from '#src/test-utils/nanoid.js';
import { MockTenant } from '#src/test-utils/tenant.js';
import { createRequester } from '#src/utils/test-utils.js';

const { jest } = import.meta;

const resources = {
  findTotalNumberOfResources: async () => ({ count: 10 }),
  findAllResources: async (): Promise<Resource[]> => [mockResource],
  findResourceByIndicator: jest.fn(async (indicator: string): Promise<Nullable<Resource>> => {
    if (indicator === mockResource.indicator) {
      return mockResource;
    }
    return null;
  }),
  findResourceById: jest.fn(async (): Promise<Resource> => mockResource),
  insertResource: jest.fn(
    async (body: CreateResource): Promise<Resource> => ({
      ...mockResource,
      ...body,
    })
  ),
  updateResourceById: async (_: unknown, data: Partial<CreateResource>): Promise<Resource> => ({
    ...mockResource,
    ...data,
  }),
  deleteResourceById: jest.fn(),
  findScopesByResourceId: async () => [mockScope],
};

const scopes = {
  findScopesByResourceId: async () => [mockScope],
  searchScopesByResourceId: async () => [mockScope],
  countScopesByResourceId: async () => ({ count: 1 }),
  findScopesByResourceIds: async () => [],
  insertScope: jest.fn(async () => mockScope),
  updateScopeById: jest.fn(async () => mockScope),
  deleteScopeById: jest.fn(),
  findScopeByNameAndResourceId: jest.fn(),
};

await mockIdGenerators();

const tenantContext = new MockTenant(undefined, { scopes, resources }, undefined);

const resourceRoutes = await pickDefault(import('./resource.js'));

describe('resource routes', () => {
  const resourceRequest = createRequester({ authedRoutes: resourceRoutes, tenantContext });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('GET /resources', async () => {
    const response = await resourceRequest.get('/resources');
    expect(response.status).toEqual(200);
    expect(response.body).toEqual([mockResource]);
    expect(response.header).not.toHaveProperty('total-number');
  });

  it('GET /resources?page=1', async () => {
    const response = await resourceRequest.get('/resources?page=1');
    expect(response.status).toEqual(200);
    expect(response.body).toEqual([mockResource]);
    expect(response.header).toHaveProperty('total-number', '10');
  });

  it('GET /resources?includeScopes=true', async () => {
    const response = await resourceRequest.get('/resources?includeScopes=true');
    expect(response.status).toEqual(200);
    expect(response.body).toEqual([{ ...mockResource, scopes: [] }]);
  });

  it('POST /resources', async () => {
    const name = 'user api';
    const indicator = 'logto.dev/user';
    const accessTokenTtl = 60;

    const response = await resourceRequest
      .post('/resources')
      .send({ name, indicator, accessTokenTtl });

    expect(response.status).toEqual(201);
    expect(response.body).toEqual({
      tenantId: 'fake_tenant',
      id: mockId,
      name,
      indicator,
      isDefault: false,
      accessTokenTtl,
      scopes: [],
    });
  });

  it('POST /resources should throw with invalid input body', async () => {
    const name = 'user api';
    const indicator = 'logto.dev/user';

    await expect(resourceRequest.post('/resources')).resolves.toHaveProperty('status', 400);
    await expect(resourceRequest.post('/resources').send({ name })).resolves.toHaveProperty(
      'status',
      400
    );
    await expect(resourceRequest.post('/resources').send({ indicator })).resolves.toHaveProperty(
      'status',
      400
    );
  });

  it('POST /resource should throw with duplicated indicator', async () => {
    const name = 'user api';
    const { indicator } = mockResource;
    const accessTokenTtl = 60;

    await expect(
      resourceRequest.post('/resources').send({ name, indicator, accessTokenTtl })
    ).resolves.toHaveProperty('status', 422);
  });

  it.each([
    'urn:aster:resource:management',
    'urn:aster:resource:management:tenant-a',
    'urn:aster:resource:management:tenant%ZZ',
    'urn:aster:resource:management:tenant:path',
    'urn:aster:resource:account',
    'urn:aster:resource:organizations',
  ])('POST /resources rejects the reserved indicator %s before persistence', async (indicator) => {
    const response = await resourceRequest
      .post('/resources')
      .send({ name: 'reserved resource', indicator, accessTokenTtl: 60 });

    expect(response.status).toBe(422);
    expect(resources.findResourceByIndicator).not.toHaveBeenCalled();
    expect(resources.insertResource).not.toHaveBeenCalled();
  });

  it.each([
    'urn:aster:resource:account:custom',
    'https://api.example.com/urn:aster:resource:management:tenant',
  ])('POST /resources allows the non-reserved indicator %s', async (indicator) => {
    const response = await resourceRequest
      .post('/resources')
      .send({ name: 'custom resource', indicator, accessTokenTtl: 60 });

    expect(response.status).toBe(201);
    expect(resources.findResourceByIndicator).toHaveBeenCalledWith(indicator);
    expect(resources.insertResource).toHaveBeenCalledTimes(1);
  });

  it('GET /resources/:id', async () => {
    const response = await resourceRequest.get('/resources/foo');

    expect(response.status).toEqual(200);
    expect(response.body).toEqual({
      ...mockResource,
    });
  });

  it('PATCH /resources/:id', async () => {
    const name = 'user api';
    const indicator = 'logto.dev/user';
    const accessTokenTtl = 60;

    const response = await resourceRequest
      .patch('/resources/foo')
      .send({ name, indicator, accessTokenTtl });

    expect(response.status).toEqual(200);
    expect(response.body).toEqual({
      ...mockResource,
      name,
      accessTokenTtl,
    });
  });

  it('PATCH /resources/:id should throw with invalid properties', async () => {
    const response = await resourceRequest.patch('/resources/foo').send({ name: 12 });
    expect(response.status).toEqual(400);
  });

  it('PATCH /resources/:id should throw when trying to modify management API', async () => {
    const { findResourceById } = resources;
    findResourceById.mockResolvedValueOnce({
      ...mockResource,
      indicator: getManagementApiResourceIndicator('mock'),
    });
    await expect(resourceRequest.patch('/resources/foo')).resolves.toHaveProperty('status', 400);
  });

  it('DELETE /resources/:id', async () => {
    await expect(resourceRequest.delete('/resources/foo')).resolves.toHaveProperty('status', 204);
  });

  it('DELETE /resources/:id should throw when trying to delete management API', async () => {
    const { findResourceById } = resources;
    findResourceById.mockResolvedValueOnce({
      ...mockResource,
      indicator: getManagementApiResourceIndicator('mock'),
    });
    await expect(resourceRequest.delete('/resources/foo')).resolves.toHaveProperty('status', 400);
  });

  it('DELETE /resources/:id should throw with invalid id', async () => {
    const { deleteResourceById } = resources;
    deleteResourceById.mockRejectedValueOnce(new Error('not found'));

    await expect(resourceRequest.delete('/resources/foo')).resolves.toHaveProperty('status', 500);
  });
});
