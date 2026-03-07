<?php

namespace App\Infrastructure\Authorization;

use App\Infrastructure\Authorization\Mappings\RolePermissionMap;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

final class PermissionRegistrar
{
    public static function sync(): void
    {
        foreach (RolePermissionMap::map() as $role => $permissions) {
            $roleModel = Role::firstOrCreate([
                'name' => $role,
                'guard_name' => 'web',
            ]);

            $permissionModels = [];

            foreach ($permissions as $permission) {
                $permissionModels[] = Permission::firstOrCreate([
                    'name' => $permission,
                    'guard_name' => 'web',
                ]);
            }

            $roleModel->syncPermissions($permissionModels);
        }

        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();
    }
}