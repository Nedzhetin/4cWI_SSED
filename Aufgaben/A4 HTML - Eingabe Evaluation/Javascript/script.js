$(document).ready(function() {
    // Parsley auf das Formular anwenden
    $('#myForm').parsley();

    // Event bei erfolgreichem Submit
    $('#myForm').on('submit', function(e) {
        e.preventDefault(); // Formular nicht automatisch senden
        if ($(this).parsley().isValid()) {
            // Alle Eingaben holen
            const text = $('input[name="textInput"]').val();
            const email = $('input[name="emailInput"]').val();
            const password = $('input[name="passwordInput"]').val();
            const tel = $('input[name="telInput"]').val();
            const url = $('input[name="urlInput"]').val();
            const search = $('input[name="searchInput"]').val();

            // Ausgabe sanitized in der Seite anzeigen
            $('#output').html(
                `<p><strong>Text:</strong> ${DOMPurify.sanitize(text)}</p>
                 <p><strong>Email:</strong> ${DOMPurify.sanitize(email)}</p>
                 <p><strong>Password:</strong> ${DOMPurify.sanitize(password)}</p>
                 <p><strong>Tel:</strong> ${DOMPurify.sanitize(tel)}</p>
                 <p><strong>URL:</strong> ${DOMPurify.sanitize(url)}</p>
                 <p><strong>Search:</strong> ${DOMPurify.sanitize(search)}</p>`
            );

            alert('Formular erfolgreich validiert! Ready to send to server.');
        }
    });
});
