<?php

namespace App\Infrastructure\Authorization\Mappings;

final class RolePermissionMap
{
    public static function map(): array
    {
        return [
            /*
             * Admins can perform ANY action
             * on core business aggregates.
             * Wildcards are intentional here.
             */
            'admin' => [
                'program.*',
                'cohort.*',
                'cohortSession.*',
                'order.*',
                'user.*',
                'certificate.*',
            ],

            /*
             * Instructors have LIMITED, explicit capabilities.
             * No wildcards here to avoid privilege creep.
             */
            'instructor' => [
                'program.create',
                'module.create',
                'lesson.create',
                'cohortSession.manage',
                'cohortSession.join',
                'cohortSession.upload_recording',
                'cohort.view_roster',
            ],

            /*
             * Students have read-only, narrow permissions.
             */
            'student' => [
                'cohort.view',
                'course.view',
            ],
        ];
    }
}