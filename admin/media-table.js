function initializeMediaTable(table, bulkButton) {
    const selectAll = table.querySelector('[data-media-select-all]');
    const selections = () => Array.from(table.querySelectorAll('tbody input[name="files[]"]'));
    const update = () => {
        const boxes = selections();
        const count = boxes.filter(box => box.checked).length;
        selectAll.checked = boxes.length > 0 && count === boxes.length;
        selectAll.indeterminate = count > 0 && count < boxes.length;
        selectAll.disabled = boxes.length === 0;
        bulkButton.disabled = count === 0;
        bulkButton.textContent = `Geselecteerde bestanden verwijderen (${count})`;
    };
    selectAll.addEventListener('change', () => {
        selections().forEach(box => { box.checked = selectAll.checked; });
        update();
    });
    table.addEventListener('change', update);
    let sortKey = 'filename';
    let direction = 1;
    const sort = () => {
        const body = table.tBodies[0];
        const rows = Array.from(body.rows).filter(row => row.dataset.filename !== undefined);
        rows.sort((a, b) => {
            const comparison = sortKey === 'size'
                ? Number(a.dataset.size) - Number(b.dataset.size)
                : a.dataset[sortKey].localeCompare(b.dataset[sortKey], 'nl', { numeric: true, sensitivity: 'base' });
            return direction * (comparison || a.dataset.filename.localeCompare(b.dataset.filename, 'nl', { numeric: true }));
        });
        rows.forEach(row => body.append(row));
        table.querySelectorAll('[data-media-sort]').forEach(button => {
            const active = button.dataset.mediaSort === sortKey;
            button.closest('th').setAttribute('aria-sort', active ? (direction === 1 ? 'ascending' : 'descending') : 'none');
            button.querySelector('[data-sort-indicator]').textContent = active ? (direction === 1 ? ' [ASC]' : ' [DESC]') : '';
        });
    };
    table.querySelectorAll('[data-media-sort]').forEach(button => {
        button.addEventListener('click', () => {
            direction = sortKey === button.dataset.mediaSort ? -direction : 1;
            sortKey = button.dataset.mediaSort;
            sort();
        });
    });
    const refresh = () => { sort(); update(); };
    refresh();
    return refresh;
}
