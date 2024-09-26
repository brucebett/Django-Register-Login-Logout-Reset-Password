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
            
        except User.DoesNotExist:
            messages.error(request, f"No user with such email '{email}' found")
            return redirect('forgot-password')
        
    return render(request, 'forgot_password.html')


def PasswordresetSent(request, reset_id):
    return render(request, 'password_reset_sent.html')


def ResetPassword(request):
    return render(request, 'reset_password.html')