<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class VerifyChangeEmail extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     */
    public function __construct(public string $token)
    {
        //
    }

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Verify your new email address')
            ->line('A request was made to change the email address on your account.')
            ->line('To confirm this change, please use the verification code below:')
            ->line('**' . $this->token . '**')
            ->line('If you did NOT request this change, someone may have access to your account.')
            ->line('We recommend that you:')
            ->line('• Do not share this code with anyone')
            ->line('• Change your password immediately')
            ->line('• Review recent account activity')
            ->line('The email change will not be completed unless this code is verified.');
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            //
        ];
    }
}
