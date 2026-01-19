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
use Illuminate\Support\Facades\Password;
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

    // =========================================================================
    // REGISTRATION & LOGIN
    // =========================================================================

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

        // Expect exactly these arguments
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
    public function test_login_returns_token_when_mfa_not_required()
    {
        // Arrange
        $user = new User(['id' => 1, 'password' => Hash::make('password')]);
        $data = ['email' => 'test@radixia.com', 'password' => 'password', 'device_name' => 'Web'];

        $this->userRepo->shouldReceive('findByEmail')->andReturn($user);

        // Mock Hash check
        Hash::shouldReceive('check')->with('password', $user->password)->andReturn(true);

        // Mock MFA check (Return NULL when no MFA is required, based on your code)
        $this->mfaService->shouldReceive('checkMfaRequirement')
            ->with($user, $data)
            ->andReturn(null);

        $this->tokenRepo->shouldReceive('create')->andReturn('valid-token');

        // Act
        $result = $this->authService->login($data, '127.0.0.1', 'UnitTestAgent');

        // Assert
        $this->assertEquals('valid-token', $result['token']);
    }

    // =========================================================================
    // MFA LOGIC
    // =========================================================================

    /**
     * @throws Throwable
     */
    public function test_login_returns_challenge_when_mfa_is_required()
    {
        // Arrange
        $user = new User(['id' => 1, 'password' => 'hashed_password']);
        $data = ['email' => 'test@radixia.com', 'password' => 'password', 'device_name' => 'Web'];

        $this->userRepo->shouldReceive('findByEmail')->andReturn($user);
        Hash::shouldReceive('check')->andReturn(true);

        // Mock MFA Check -> REQUIRED
        $this->mfaService->shouldReceive('checkMfaRequirement')
            ->with($user, $data)
            ->andReturn(['mfa_required' => true]); // Your service returns this array

        // Expect Temp Token Creation for MFA
        $this->tokenRepo->shouldReceive('create')
            ->once()
            ->with($user, 'login-mfa-pending', '127.0.0.1', 'UnitTestAgent', ['mfa:verify'])
            ->andReturn('temp-mfa-token');

        // Act
        $result = $this->authService->login($data, '127.0.0.1', 'UnitTestAgent');

        // Assert
        $this->assertTrue($result['mfa_required']);
        $this->assertEquals('temp-mfa-token', $result['token']);
    }

    // =========================================================================
    // PASSWORD RESET LOGIC
    // =========================================================================

    public function test_forgot_password_returns_link_sent_status()
    {
        // Arrange
        $data = ['email' => 'test@radixia.com'];
        // Use a real user instance but mock the notify method via partial mock if needed,
        // OR just rely on the fact that your service code calls notify.

        // Simpler approach: Just verify the service returns "passwords.sent"
        // We need to mock the UserRepo to return a user
        $user = Mockery::mock(User::class)->makePartial();
        $user->email = 'test@radixia.com';
        $user->shouldReceive('notify')->once(); // Expect notification

        $this->userRepo->shouldReceive('findByEmail')
            ->once()
            ->with('test@radixia.com')
            ->andReturn($user);

        // Mock Password Facade for token generation
        $brokerMock = Mockery::mock(PasswordBroker::class);
        $brokerMock->shouldReceive('createToken')->andReturn('token_123');
        Password::shouldReceive('broker')->andReturn($brokerMock);

        // Act
        $status = $this->authService->forgotPassword($data, null);

        // Assert
        $this->assertEquals(Password::RESET_LINK_SENT, $status);
    }

}
