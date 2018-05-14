from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from config.settings.base import ALLOWED_SIGNUP_DOMAINS


def SignupDomainValidator(value):
    if '*' not in ALLOWED_SIGNUP_DOMAINS:
        try:
            domain = value[value.index("@"):]
            if domain not in ALLOWED_SIGNUP_DOMAINS:
                raise ValidationError('Invalid domain. Allowed domains on this network: {0}'.format(','.join(ALLOWED_SIGNUP_DOMAINS)))  # noqa: E501

        except Exception:
            raise ValidationError('Invalid domain. Allowed domains on this network: {0}'.format(','.join(ALLOWED_SIGNUP_DOMAINS)))  # noqa: E501


def ForbiddenUsernamesValidator(value):
    forbidden_usernames = ['admin', 'settings', 'news', 'about', 'help',
                           'signin', 'signup', 'signout', 'terms', 'privacy',
                           'cookie', 'new', 'login', 'logout', 'administrator',
                           'join', 'account', 'username', 'root', 'blog',
                           'user', 'users', 'billing', 'subscribe', 'reviews',
                           'review', 'blog', 'blogs', 'edit', 'mail', 'email',
                           'home', 'job', 'jobs', 'contribute', 'newsletter',
                           'shop', 'profile', 'register', 'auth',
                           'authentication', 'campaign', 'config', 'delete',
                           'remove', 'forum', 'forums', 'download',
                           'downloads', 'contact', 'blogs', 'feed', 'feeds',
                           'faq', 'intranet', 'log', 'registration', 'search',
                           'explore', 'rss', 'support', 'status', 'static',
                           'media', 'setting', 'css', 'js', 'follow',
                           'activity', 'questions', 'articles', 'network', ]

    if value.lower() in forbidden_usernames:
        raise ValidationError('Введие другое имя пользователя.')


def InvalidUsernameValidator(value):
    if '@' in value or '+' in value or '-' in value:
        raise ValidationError('Введите верное имя пользователя.')


def UniqueEmailValidator(value):
    if User.objects.filter(email__iexact=value).exists():
        raise ValidationError('Пользователь с таким email уже существует.')


def UniqueUsernameIgnoreCaseValidator(value):
    if User.objects.filter(username__iexact=value).exists():
        raise ValidationError('Пользователь с таким именем уже существует.')


class SignUpForm(forms.ModelForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        label="Имя пользователя",
        max_length=30,
        required=True,
        help_text='Имя пользователя может содержать латинские и кириллические буквы, цифры, символы <strong>_</strong> и <strong>.</strong>')  # noqa: E501
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        label = "Пароль")
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        label="Подтверждение пароля",
        required=True)
    email = forms.CharField(
        widget=forms.EmailInput(attrs={'class': 'form-control'}),
        required=True,
        max_length=75)

    class Meta:
        model = User
        exclude = ['last_login', 'date_joined']
        fields = ['username', 'email', 'password', 'confirm_password', ]

    def __init__(self, *args, **kwargs):
        super(SignUpForm, self).__init__(*args, **kwargs)
        self.fields['username'].validators.append(ForbiddenUsernamesValidator)
        self.fields['username'].validators.append(InvalidUsernameValidator)
        self.fields['username'].validators.append(
            UniqueUsernameIgnoreCaseValidator)
        self.fields['email'].validators.append(UniqueEmailValidator)
        self.fields['email'].validators.append(SignupDomainValidator)

    def clean(self):
        super(SignUpForm, self).clean()
        password = self.cleaned_data.get('password')
        confirm_password = self.cleaned_data.get('confirm_password')
        if password and password != confirm_password:
            self._errors['password'] = self.error_class(
                ['Passwords don\'t match'])
        return self.cleaned_data
