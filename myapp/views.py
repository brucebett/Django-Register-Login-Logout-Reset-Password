from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from .models import *


@login_required
def Home(request):
    return render(request, 'index.html')

def RegisterView(request):

    if request.method =='POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        User_data_has_error = False

        if User.objects.filter(username=username).exists():
            User_data_has_error = True
            messages.error(request, "Username already exist")

        if User.objects.filter(email=email).exists():
            User_data_has_error = True
            messages.error(request, "Email already exist")   

        if len(password) < 5:
            User_data_has_error = True
            messages.error(request, "Password must be atleast 5 characters")    

        if User_data_has_error:
            return redirect('register')   
        else:
            new_user = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                username=username,
                password=password
            )
            messages.success(request, 'Account create successfuly, login now')
            return redirect('login')
 
    return render(request, 'register.html')



def  LoginView(request):

    if request.method == 'POST':
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            return redirect('home')
        else:
            messages.error(request, "Invalid login credentials")
            return redirect('login')
    return render(request, 'login.html')


def LogoutView(request):
    logout(request)
    return redirect('login')


def ForgotPassword(request):

    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            password_reset_url = reverse('reset_password', kwargs={'reset_id': new_password_reset.reset_id})
            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'
            email_body = f'Reset your password in the link below:\n\n\n{password_reset_url}'
        
            email_message = EmailMessage(
                'Reset your password',
                email_body,
                settings.EMAIL_HOST_USER,
                [email]
            )

            email_message.fail_silently = True
            email_message.send()

            return redirect('password_reset_sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request, f"No user with such email '{email}' found")
            return redirect('forgot-password')
        
    return render(request, 'forgot_password.html')


def PasswordresetSent(request, reset_id):

    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')
    else:
        messages.error(request, 'Invalid reset id')
        return redirect('forgot_password')
    
 

def ResetPassword(request, reset_id):
    try:
        # Retrieve the PasswordReset instance using the reset_id
        password_reset_instance = PasswordReset.objects.get(reset_id=reset_id)

        # Check if the request method is POST
        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            passwords_have_error = False

            # Check if passwords match
            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Passwords do not match')

            # Check password length
            if len(password) < 5:
                passwords_have_error = True
                messages.error(request, "Password must be at least 5 characters long")

            # Check if the reset link has expired
            expiration_time = password_reset_instance.created_when + timezone.timedelta(minutes=10)
            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, 'Reset link has expired')

                # Delete the expired password reset instance
                password_reset_instance.delete()
                return redirect('forgot-password')  # Redirect after expiration

            # If no errors, proceed to reset the password
            if not passwords_have_error:
                user = password_reset_instance.user
                user.set_password(password)  # Hash the password
                user.save()

                # Delete the password reset instance
                password_reset_instance.delete()

                messages.success(request, 'Password reset successfully. Proceed to login.')
                return redirect('login')

        # Render the reset password template
        return render(request, 'reset_password.html', {'reset_id': reset_id})

    except PasswordReset.DoesNotExist:
        messages.error(request, 'Invalid reset ID')
        return redirect('forgot-password')