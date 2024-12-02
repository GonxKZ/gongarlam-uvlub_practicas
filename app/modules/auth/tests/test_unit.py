import pytest
from flask import url_for

from app.modules.auth.services import AuthenticationService
from app.modules.auth.repositories import UserRepository
from app.modules.profile.repositories import UserProfileRepository


@pytest.fixture(scope="module")
def test_client_with_data(test_client):
    """
    Extiende el fixture test_client para añadir datos específicos para pruebas adicionales.
    """
    with test_client.application.app_context():
        # Añade aquí los elementos nuevos a la base de datos que deseas que existan en el contexto de prueba.
        # Por ejemplo, crear un usuario de prueba.
        auth_service = AuthenticationService()
        auth_service.create_with_profile(
            name="Test",
            surname="User",
            email="test@example.com",
            password="test1234"
        )
        auth_service.create_with_profile(
            name="Existing",
            surname="User",
            email="existing@example.com",
            password="existing123"
        )
        auth_service.create_with_profile(
            name="Another",
            surname="User",
            email="another@example.com",
            password="another123"
        )
    
    yield test_client


@pytest.fixture
def login_user(test_client_with_data):
    """
    Fixture para autenticar al usuario de prueba antes de ejecutar una prueba.
    """
    test_client_with_data.post(
        "/login", data=dict(email="test@example.com", password="test1234"), follow_redirects=True
    )
    return test_client_with_data


# 1. Pruebas de Inicio de Sesión sin Email o Contraseña

def test_login_no_email(test_client_with_data):
    response = test_client_with_data.post(
        "/login", data=dict(password="test1234"), follow_redirects=True
    )
    assert response.request.path == url_for("auth.login"), "Login debería fallar sin email"
    assert b"Este campo es requerido" in response.data, "Debe mostrar mensaje de campo requerido"


def test_login_no_password(test_client_with_data):
    response = test_client_with_data.post(
        "/login", data=dict(email="test@example.com"), follow_redirects=True
    )
    assert response.request.path == url_for("auth.login"), "Login debería fallar sin contraseña"
    assert b"Este campo es requerido" in response.data, "Debe mostrar mensaje de campo requerido"


# 2. Prueba de Validación del Formato de Email en el Registro

def test_signup_invalid_email_format(test_client_with_data):
    response = test_client_with_data.post(
        "/signup",
        data=dict(name="Test", surname="User", email="invalid-email", password="test1234"),
        follow_redirects=True,
    )
    assert response.request.path == url_for("auth.show_signup_form"), "Registro debería fallar con email inválido"
    assert b"Formato de email inválido" in response.data, "Debe mostrar mensaje de formato de email inválido"


# 3. Prueba de Fortaleza de la Contraseña en el Registro

def test_signup_weak_password(test_client_with_data):
    response = test_client_with_data.post(
        "/signup",
        data=dict(name="Test", surname="User", email="weakpass@example.com", password="123"),
        follow_redirects=True,
    )
    assert response.request.path == url_for("auth.show_signup_form"), "Registro debería fallar con contraseña débil"
    assert b"La contraseña es demasiado débil" in response.data, "Debe mostrar mensaje de contraseña débil"


# 4. Prueba de Acceso a Rutas Protegidas sin Autenticación

def test_protected_route_requires_login(test_client_with_data):
    response = test_client_with_data.get("/profile", follow_redirects=True)
    assert response.request.path == url_for("auth.login"), "Debe redirigir al login si no está autenticado"
    assert b"Inicia sesión para acceder a esta página" in response.data, "Debe mostrar mensaje de inicio de sesión requerido"


# 5. Prueba de Cierre de Sesión

def test_logout(test_client_with_data):
    # Primero, inicia sesión
    test_client_with_data.post(
        "/login", data=dict(email="test@example.com", password="test1234"), follow_redirects=True
    )
    # Luego, cierra sesión
    response = test_client_with_data.get("/logout", follow_redirects=True)
    assert response.request.path == url_for("public.index"), "Debe redirigir a la página principal tras cerrar sesión"
    
    # Intenta acceder a una ruta protegida
    response = test_client_with_data.get("/profile", follow_redirects=True)
    assert response.request.path == url_for("auth.login"), "Debe redirigir al login después de cerrar sesión"


# 6. Prueba de Actualización del Perfil de Usuario

def test_update_profile_success(login_user):
    response = login_user.post(
        "/profile/update",
        data=dict(name="Updated", surname="User"),
        follow_redirects=True
    )
    assert response.request.path == url_for("profile.view"), "Debe redirigir a la vista del perfil tras actualizar"
    assert b"Perfil actualizado exitosamente" in response.data, "Debe mostrar mensaje de éxito"


def test_update_profile_invalid_data(login_user):
    response = login_user.post(
        "/profile/update",
        data=dict(name="", surname=""),
        follow_redirects=True
    )
    assert response.request.path == url_for("profile.view"), "Debe permanecer en la vista del perfil si falla la actualización"
    assert b"Los campos de nombre y apellido son requeridos" in response.data, "Debe mostrar mensajes de error"


# 7. Prueba de Eliminación de Usuario

def test_delete_user_success(login_user):
    response = login_user.post("/profile/delete", follow_redirects=True)
    assert response.request.path == url_for("public.index"), "Debe redirigir a la página principal tras eliminar la cuenta"
    assert b"Cuenta eliminada exitosamente" in response.data, "Debe mostrar mensaje de éxito"
    
    # Verifica que el usuario ya no exista en la base de datos
    assert UserRepository().count() == 2  # Porque ya habías creado 3 usuarios y eliminado uno
    assert UserProfileRepository().count() == 2


# 8. Prueba de Registro con Campos Faltantes

def test_signup_missing_fields(test_client_with_data):
    response = test_client_with_data.post(
        "/signup",
        data=dict(name="", surname="", email="", password=""),
        follow_redirects=True,
    )
    assert response.request.path == url_for("auth.show_signup_form"), "Registro debería fallar con campos faltantes"
    assert b"Este campo es requerido" in response.data, "Debe mostrar mensajes de campos requeridos"


# 9. Prueba de Registro con Email ya Registrado

def test_signup_duplicate_email(test_client_with_data):
    # Primero, crea un usuario
    response = test_client_with_data.post(
        "/signup",
        data=dict(name="Existing", surname="User", email="duplicate@example.com", password="test1234"),
        follow_redirects=True,
    )
    assert response.request.path == url_for("public.index"), "Debe redirigir a la página principal tras un registro exitoso"

    # Intenta crear otro usuario con el mismo email
    response = test_client_with_data.post(
        "/signup",
        data=dict(name="New", surname="User", email="duplicate@example.com", password="newpass123"),
        follow_redirects=True,
    )
    assert response.request.path == url_for("auth.show_signup_form"), "Registro debería fallar con email duplicado"
    assert b"El email ya está en uso" in response.data, "Debe mostrar mensaje de email en uso"


# 10. Prueba de Recuperación de Contraseña

def test_password_reset_request(test_client_with_data):
    response = test_client_with_data.post(
        "/reset_password", data=dict(email="test@example.com"), follow_redirects=True
    )
    assert response.request.path == url_for("auth.reset_password_sent"), "Debe redirigir tras solicitar el reseteo"
    assert b"Se ha enviado un correo para restablecer la contraseña" in response.data, "Debe mostrar mensaje de éxito"


def test_password_reset_invalid_email(test_client_with_data):
    response = test_client_with_data.post(
        "/reset_password", data=dict(email="nonexistent@example.com"), follow_redirects=True
    )
    assert response.request.path == url_for("auth.reset_password"), "Debe permanecer en la página de reseteo si falla"
    assert b"El email no está registrado" in response.data, "Debe mostrar mensaje de email no registrado"


# 11. Prueba de Verificación de Email

def test_email_verification_success(test_client_with_data):
    # Supongamos que tienes una función para generar tokens de verificación
    token = AuthenticationService().generate_verification_token("test@example.com")
    response = test_client_with_data.get(f"/verify_email/{token}", follow_redirects=True)
    assert response.request.path == url_for("public.index"), "Debe redirigir a la página principal tras verificar"
    assert b"Email verificado exitosamente" in response.data, "Debe mostrar mensaje de éxito"


def test_email_verification_invalid_token(test_client_with_data):
    response = test_client_with_data.get("/verify_email/invalidtoken", follow_redirects=True)
    assert response.request.path == url_for("public.index"), "Debe redirigir a la página principal incluso con token inválido"
    assert b"Token de verificación inválido o expirado" in response.data, "Debe mostrar mensaje de error"


# 12. Prueba de Acceso Concurrente y Sesiones

def test_concurrent_sessions(test_client_with_data):
    # Inicia sesión en dos clientes diferentes
    client1 = test_client_with_data
    client2 = test_client_with_data.application.test_client()
    
    response1 = client1.post(
        "/login", data=dict(email="test@example.com", password="test1234"), follow_redirects=True
    )
    response2 = client2.post(
        "/login", data=dict(email="test@example.com", password="test1234"), follow_redirects=True
    )
    
    assert response1.status_code == 200, "Cliente 1 debe iniciar sesión correctamente"
    assert response2.status_code == 200, "Cliente 2 debe iniciar sesión correctamente"
    
    # Cierra sesión en uno de los clientes
    client1.get("/logout", follow_redirects=True)
    
    # Verifica que el otro cliente aún esté autenticado
    response = client2.get("/profile")
    assert response.status_code == 200, "Cliente 2 aún debe estar autenticado"


# 13. Prueba de Rate Limiting en el Inicio de Sesión

def test_login_rate_limiting(test_client_with_data):
    for _ in range(5):
        response = test_client_with_data.post(
            "/login", data=dict(email="test@example.com", password="wrongpassword"), follow_redirects=True
        )
        assert response.request.path == url_for("auth.login"), "Cada intento incorrecto debe fallar"
    
    # Sexto intento debería estar bloqueado
    response = test_client_with_data.post(
        "/login", data=dict(email="test@example.com", password="wrongpassword"), follow_redirects=True
    )
    assert response.request.path == url_for("auth.login"), "Debe permanecer en la página de login"
    assert b"Demasiados intentos de inicio de sesión. Inténtalo más tarde." in response.data, "Debe mostrar mensaje de bloqueo"


# 14. Prueba de Acceso a Perfil de Otro Usuario

def test_access_another_user_profile(test_client_with_data, login_user):
    # Intenta acceder al perfil del otro usuario
    response = test_client_with_data.get("/profile/another@example.com", follow_redirects=True)
    assert response.request.path == url_for("public.index"), "Debe redirigir a la página principal si intenta acceder a otro perfil"
    assert b"No tienes permiso para ver este perfil" in response.data, "Debe mostrar mensaje de permiso denegado"


# 15. Prueba de Actualización de Email con Email Ya Registrado

def test_update_profile_duplicate_email(test_client_with_data, login_user):
    # Intenta actualizar el email del usuario actual a un email existente
    response = login_user.post(
        "/profile/update",
        data=dict(name="Test", surname="User", email="existing@example.com"),
        follow_redirects=True
    )
    assert response.request.path == url_for("profile.view"), "Debe permanecer en la vista del perfil si falla la actualización"
    assert b"El email ya está en uso" in response.data, "Debe mostrar mensaje de email en uso"
