from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User

class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.profile_url = reverse('profile')
        self.home_url = reverse('home')
        self.username = 'testuser'
        self.password = 'TestPass123!'
        self.user = User.objects.create_user(username=self.username, password=self.password)

    def test_home_page_status_code(self):
        response = self.client.get(self.home_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'shema/home.html')

    def test_registration_flow(self):
        response = self.client.post(self.register_url, {
            'username': 'newuser',
            'password': 'NewPass123!',
            'password_confirm': 'NewPass123!'
        })
        # UserCreationForm usually needs password1 and password2
        # Let's check the actual field names in UserCreationForm
        # By default they are username, password1, password2
        response = self.client.post(self.register_url, {
            'username': 'newuser2',
            'password1': 'NewPass123!',
            'password2': 'NewPass123!'
        })
        self.assertEqual(response.status_code, 302) # Redirect to home
        self.assertTrue(User.objects.filter(username='newuser2').exists())

    def test_login_flow(self):
        response = self.client.post(self.login_url, {
            'username': self.username,
            'password': self.password
        })
        self.assertEqual(response.status_code, 302) # Redirect to home
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_logout_flow(self):
        self.client.login(username=self.username, password=self.password)
        response = self.client.post(self.logout_url)
        self.assertEqual(response.status_code, 302)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_profile_protected_access(self):
        # Access profile without login
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

        # Access profile with login
        self.client.login(username=self.username, password=self.password)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'shema/profile.html')
