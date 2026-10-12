import { classifyManagementProvisioningClientRefusal } from './management-provisioning-family.js';

test('admits only the selected reaped ownership refusal', () => {
  expect(
    classifyManagementProvisioningClientRefusal(
      1,
      false,
      'Error: multiple applications use the Box-AI application name\n    at provision-client.mjs',
      false
    )
  ).toBe('ownership-refused');
  expect(classifyManagementProvisioningClientRefusal(1, false, 'network failure', false)).toBe(
    undefined
  );
  expect(
    classifyManagementProvisioningClientRefusal(
      1,
      true,
      'Error: multiple applications use the Box-AI application name',
      false
    )
  ).toBeUndefined();
  expect(
    classifyManagementProvisioningClientRefusal(
      1,
      false,
      'Error: multiple applications use the Box-AI application name',
      true
    )
  ).toBeUndefined();
});
