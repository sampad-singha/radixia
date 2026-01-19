<?php

namespace Tests\Unit\Application\Auth;

use App\Application\Auth\Services\AuthService;
use App\Domain\Auth\Exceptions\InvalidCredentialsException;
use App\Domain\Auth\Repositories\AccessTokenRepositoryInterface;
use App\Domain\Mfa\Services\MfaServiceInterface;
use App\Domain\Users\Repositories\UserRepositoryInterface;
use App\Models\User;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Laravel\Fortify\Contracts\ResetsUserPasswords;
use Mockery;
use Mockery\MockInterface;
use Tests\TestCase;
use Throwable;

class AuthServiceTest extends TestCase
{
    private UserRepositoryInterface|MockInterface $userRepo;
    private AccessTokenRepositoryInterface|MockInterface $tokenRepo;
    private CreatesNewUsers|MockInterface $creator;
    private ResetsUserPasswords|MockInterface $resetter;
    private PasswordBroker|MockInterface $broker;
    private MfaServiceInterface|MockInterface $mfaService;
    private AuthService $authService;

    protected function setUp(): void
    {
        parent::setUp();

        // 1. Mock all dependencies
        $this->userRepo = Mockery::mock(UserRepositoryInterface::class);
        $this->tokenRepo = Mockery::mock(AccessTokenRepositoryInterface::class);
        $this->creator = Mockery::mock(CreatesNewUsers::class);
        $this->resetter = Mockery::mock(ResetsUserPasswords::class);
        $this->broker = Mockery::mock(PasswordBroker::class);
        $this->mfaService = Mockery::mock(MfaServiceInterface::class);

        // 2. Inject mocks into AuthService
        $this->authService = new AuthService(
            $this->userRepo,
            $this->tokenRepo,
            $this->creator,
            $this->resetter,
            $this->broker,
            $this->mfaService
        );
    }

    public function test_register_creates_user_and_token()
    {
        // Arrange
        $data = ['email' => 'test@radixia.com', 'password' => 'password', 'device_name' => 'TestDevice'];
        $user = new User(['id' => 1, 'email' => 'test@radixia.com']);

        Event::fake();

        $this->creator->shouldReceive('create')
            ->once()
            ->with($data)
            ->andReturn($user);

        // FIX: Match the exact IP ('127.0.0.1') and Agent ('UnitTestAgent') you pass below
        $this->tokenRepo->shouldReceive('create')
            ->once()
            ->with($user, 'TestDevice', '127.0.0.1', 'UnitTestAgent')
            ->andReturn('plain-text-token');

        // Act
        $result = $this->authService->register($data, '127.0.0.1', 'UnitTestAgent');

        // Assert
        $this->assertEquals('plain-text-token', $result['token']);
        $this->assertEquals($user, $result['user']);
    }

    /**
     * @throws Throwable
     */
    public function test_login_throws_exception_on_invalid_credentials()
    {
        // Arrange
        $data = ['email' => 'wrong@radixia.com', 'password' => 'wrong-pass'];

        $this->userRepo->shouldReceive('findByEmail')
            ->once()
            ->with('wrong@radixia.com')
            ->andReturn(null); // User not found

        // Assert
        $this->expectException(InvalidCredentialsException::class);

        // Act
        $this->authService->login($data, '127.0.0.1', 'UnitTestAgent');
    }

    /**
     * @throws Throwable
     */
    public function test_login_returns_token_on_success()
    {
        // Arrange
        $user = new User(['id' => 1, 'password' => Hash::make('password')]);
        $data = ['email' => 'test@radixia.com', 'password' => 'password', 'device_name' => 'Web'];

        $this->userRepo->shouldReceive('findByEmail')->andReturn($user);

        // Mock Hash check (Laravel facade)
        Hash::shouldReceive('check')->with('password', $user->password)->andReturn(true);

        // Mock MFA check (return false = no MFA required)
        $this->mfaService->shouldReceive('checkMfaRequirement')
            ->with($user, $data)
            ->andReturn(['required' => false]);

        $this->tokenRepo->shouldReceive('create')->andReturn('valid-token');

        // Act
        $result = $this->authService->login($data, '127.0.0.1', 'UnitTestAgent');

        // Assert
        $this->assertEquals('valid-token', $result['token']);
    }
}
