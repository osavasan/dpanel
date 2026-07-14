$(document).ready(function () {
    // Docker Stats page
    if (window.location.pathname.startsWith("/dockerstats")) {
        if ($('#dockerStats').length) {
            $('#dockerStats').DataTable({
                "order": [[2, "desc"]]
            });
        }

        // stop container handler
        $(document).on('click', '.btn-stop', function (e) {
            e.preventDefault();
            var id = $(this).data('id');
            if (!id) return;
            if (!confirm('Stop container ' + id + '?')) return;
            fetch('/docker/stop', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: id })
            }).then(function (res) {
                if (!res.ok) return res.text().then(function (t) { throw new Error(t || 'stop failed'); });
                return res.json();
            }).then(function (data) {
                location.reload();
            }).catch(function (err) {
                alert('Failed to stop container: ' + err.message);
            });
        });
    }

    // Dockerfiles editor handlers
    if (window.location.pathname.startsWith("/dockerfiles")) {
        // open modal and load file
        $(document).on('click', '.btn-edit-dockerfile', function (e) {
            e.preventDefault();
            var path = $(this).data('path');
            if (!path) return;

            $('#yamlFilePath').text(path);
            $('#yamlEditorAlert').hide().text('');
            fetch('/dockerfiles/file?path=' + encodeURIComponent(path)).then(function (res) {
                if (!res.ok) return res.text().then(function (t) { throw new Error(t || 'failed to load file'); });
                return res.json();
            }).then(function (data) {
                $('#yamlEditor').val(data.content);
                var modalEl = document.getElementById('yamlEditModal');
                var modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
                modal.show();
            }).catch(function (err) {
                alert('Error loading file: ' + err.message);
            });
        });

        // save handler
        $(document).on('click', '#yamlSaveBtn', function (e) {
            e.preventDefault();
            var path = $('#yamlFilePath').text();
            var content = $('#yamlEditor').val();

            // client-side YAML validation if jsyaml is available
            if (window.jsyaml) {
                try {
                    jsyaml.load(content);
                } catch (e) {
                    $('#yamlEditorAlert').show().text('YAML validation error: ' + e.message);
                    return;
                }
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

    // Nginx configs editor handlers
    if (window.location.pathname.startsWith("/nginxconfigs")) {
        // open modal and load file
        $(document).on('click', '.btn-view-nginx', function (e) {
            e.preventDefault();
            var path = $(this).data('path');
            if (!path) return;

            $('#nginxFilePath').text(path);
            $('#nginxEditorAlert').hide().text('');

            fetch('/nginxconfigs/file?path=' + encodeURIComponent(path)).then(function (res) {
                if (!res.ok) {
                    return res.text().then(function (t) { throw new Error(t || 'failed to load file'); });
                }
                return res.json();
            }).then(function (data) {
                $('#nginxEditor').val(data.content);
                var modalEl = document.getElementById('nginxEditModal');
                var modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
                modal.show();
            }).catch(function (err) {
                alert('Error loading file: ' + err.message);
            });
        });

        // save handler
        $(document).on('click', '#nginxSaveBtn', function (e) {
            e.preventDefault();
            var path = $('#nginxFilePath').text();
            var content = $('#nginxEditor').val();
            fetch('/nginxconfigs/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: path, content: content })
            }).then(function (res) {
                if (!res.ok) {
                    return res.text().then(function (t) { throw new Error(t || 'save failed'); });
                }
                return res.json();
            }).then(function (data) {
                var modalEl = document.getElementById('nginxEditModal');
                var modal = bootstrap.Modal.getInstance(modalEl);
                if (modal) modal.hide();
                alert('File saved successfully!');
            }).catch(function (err) {
                $('#nginxEditorAlert').show().text('Save failed: ' + err.message);
            });
        });
    }

    // Auth Log page
    if (window.location.pathname.startsWith("/authlog")) {
        if ($('#authLogTable').length) {
            var authTable = $('#authLogTable').DataTable({
                "order": [],
                "pageLength": 100,
                "dom": "<'row'<'col-sm-12 col-md-6'l><'col-sm-12 col-md-6'>>" +
                       "<'row'<'col-sm-12'tr>>" +
                       "<'row'<'col-sm-12 col-md-5'i><'col-sm-12 col-md-7'p>>"
            });
            $('#customFilter').on('keyup', function () {
                authTable.search(this.value).draw();
            });
        }
    }
});