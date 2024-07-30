const canvas = document.getElementById('signature-pad');
const clearButton = document.getElementById('clear');
const ctx = canvas.getContext('2d');
let drawing = false;

canvas.addEventListener('mousedown', () => {
    drawing = true;
    ctx.beginPath();
});

canvas.addEventListener('mouseup', () => {
    drawing = false;
});

canvas.addEventListener('mousemove', (event) => {
    if (drawing) {
        ctx.lineTo(event.offsetX, event.offsetY);
        ctx.stroke();
    }
});

canvas.addEventListener('touchstart', (event) => {
    drawing = true;
    const touch = event.touches[0];
    ctx.beginPath();
    ctx.moveTo(touch.clientX - canvas.offsetLeft, touch.clientY - canvas.offsetTop);
});

canvas.addEventListener('touchend', () => {
    drawing = false;
});

canvas.addEventListener('touchmove', (event) => {
    if (drawing) {
        const touch = event.touches[0];
        ctx.lineTo(touch.clientX - canvas.offsetLeft, touch.clientY - canvas.offsetTop);
        ctx.stroke();
    }
});

clearButton.addEventListener('click', () => {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
});

document.getElementById('dataForm').addEventListener('submit', (event) => {
    event.preventDefault();
    const dataURL = canvas.toDataURL();
    const formData = new FormData(event.target);
    formData.append('signature', dataURL);

    fetch('/submit', {
        method: 'POST',
        body: formData
    }).then(response => {
        if (response.ok) {
            alert('提交成功');
            event.target.reset();
            ctx.clearRect(0, 0, canvas.width, canvas.height);
        } else {
            alert('提交失败');
        }
    });
});