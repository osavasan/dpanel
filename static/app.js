$(document).ready(function () {
    if (window.location.pathname === "/dockerstats") {
        $('#dockerStats').DataTable({
            "order": [[2, "desc"]]
        });
    }
    // Dockerfiles editor handlers
    if (window.location.pathname === "/dockerfiles") {
        // open modal and load file
        $(document).on('click', '.btn-edit-dockerfile', function (e) {
            var path = $(this).data('path');
            $('#yamlFilePath').text(path);
            $('#yamlEditorAlert').hide().text('');
            fetch('/dockerfiles/file?path=' + encodeURIComponent(path)).then(function (res) {
                if (!res.ok) throw new Error('failed to load file');
                return res.json();
            }).then(function (data) {
                $('#yamlEditor').val(data.content);
                var modal = new bootstrap.Modal(document.getElementById('yamlEditModal'));
                modal.show();
            }).catch(function (err) {
                alert('Error loading file: ' + err.message);
            });
        });

        // save handler with client-side YAML validation
        $('#yamlSaveBtn').on('click', function () {
            var path = $('#yamlFilePath').text();
            var content = $('#yamlEditor').val();
            try {
                jsyaml.load(content);
            } catch (e) {
                $('#yamlEditorAlert').show().text('YAML validation error: ' + e.message);
                return;
            }
            fetch('/dockerfiles/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: path, content: content })
            }).then(function (res) {
                if (!res.ok) return res.text().then(function (t) { throw new Error(t || 'save failed'); });
                return res.json();
            }).then(function (data) {
                var modalEl = document.getElementById('yamlEditModal');
                var modal = bootstrap.Modal.getInstance(modalEl);
                if (modal) modal.hide();
                location.reload();
            }).catch(function (err) {
                $('#yamlEditorAlert').show().text('Save failed: ' + err.message);
            });
        });
    }
});