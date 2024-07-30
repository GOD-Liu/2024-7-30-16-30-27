document.addEventListener('DOMContentLoaded', () => {
    const filterDate = document.getElementById('filterDate');
    const filterOrganization = document.getElementById('filterOrganization');
    const applyFilterButton = document.getElementById('applyFilter');

    function loadSubmissions(filter = {}) {
        let query = '/submissions';
        const queryParams = new URLSearchParams(filter);
        if (queryParams.toString()) {
            query += '?' + queryParams.toString();
        }

        fetch(query)
            .then(response => response.json())
            .then(data => {
                const tableBody = document.querySelector('#submissionsTable tbody');
                tableBody.innerHTML = '';
                data.forEach(submission => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${submission.id}</td>
                        <td>${submission.name}</td>
                        <td>${submission.phone}</td>
                        <td>${submission.organization}</td>
                        <td>${submission.carPlate}</td>
                        <td><img src="${submission.signature}" alt="Signature" width="100"></td>
                        <td>${submission.submitted_at}</td>
                        <td><button data-id="${submission.id}" class="delete-button">删除</button></td>
                    `;
                    tableBody.appendChild(row);
                });

                document.querySelectorAll('.delete-button').forEach(button => {
                    button.addEventListener('click', (event) => {
                        const id = event.target.getAttribute('data-id');
                        fetch(`/submissions/${id}`, { method: 'DELETE' })
                            .then(() => loadSubmissions(filter));
                    });
                });
            });
    }

    applyFilterButton.addEventListener('click', () => {
        const filter = {
            date: filterDate.value,
            organization: filterOrganization.value
        };
        loadSubmissions(filter);
    });

    document.getElementById('download').addEventListener('click', () => {
        fetch('/download')
            .then(response => response.blob())
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'submissions.csv';
                document.body.appendChild(a);
                a.click();
                a.remove();
            });
    });

    loadSubmissions();
});