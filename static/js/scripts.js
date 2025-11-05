function confirmLogout() {
    if (confirm('Are you sure you want to logout?')) {
        window.location.href = "{{ url_for('logout') }}";
    }
}