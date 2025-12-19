$(document).ready(function () {
    if (window.location.pathname === "/dockerstats") {
        $('#dockerStats').DataTable({
            "order": [[2, "desc"]]
        });
    }
});