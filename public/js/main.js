async function submitWord() {
    const word = document.getElementById('wordInput').value;
    if (word.trim()) {
        try {
            const response = await fetch('/api/games', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ secretWord: word })
            });
            const data = await response.json();
            if (data.redirectUrl) {
                window.location.href = data.redirectUrl;
            } else {
                alert('Bir hata oluştu');
            }
        } catch (error) {
            console.error('Hata:', error);
            alert('Bir hata oluştu');
        }
    }
}

// Buton tıklama olayı
document.getElementById('submitBtn').addEventListener('click', submitWord);

// Enter tuşu olayı
document.getElementById('wordInput').addEventListener('keypress', function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        submitWord();
    }
}); 