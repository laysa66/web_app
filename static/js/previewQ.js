//on dom load with js not jquery
window.onload = function() {
    const id = window.location.hash.split('-')[1]
    if (id) {
        const element = document.getElementById(`question-${id}`)
        if (element) {
            const y = element.getBoundingClientRect().top + window.scrollY;
            window.scrollTo({top: y, behavior: 'smooth'})
        }
    }
}

function previewQuestion() { // Fonction qui permet de prévisualiser la question
    for (let questionI of document.getElementsByClassName("question")) { // Pour chaque question
        let question = questionI.getElementsByClassName("question_txt")[0].innerHTML; // Récupération de la question
        let preview = questionI.getElementsByClassName("preview")[0]; // Récupération de la div qui contient la prévisualisation
        const renderer = new marked.Renderer(); // Création d'un nouveau renderer
        renderer.text = function (text) { // Fonction qui permet de gérer le rendu des textes latex
            try {
                return katex.renderToString(text);
            }
            catch (e) {
                return text;
            }
        }
        renderer.code = function (code, language) { // Fonction qui permet de gérer le rendu des codes mermaid et des codes classiques
            if (language === "mermaid") {
                return `<div class="mermaid">${code}</div>`;
            }
            return `<pre><code class="hljs ${language}">${code}</code></pre>`;
        }
        marked.setOptions({
            renderer: renderer,
            gfm: true,
            breaks: true,
            highlight: function (code, language) {
                if (language === "mermaid") {
                    return code;
                }
                return hljs.highlightAuto(code).value;
            }
        })
        preview.innerHTML = marked(question);
        mermaid.init();
        questionI.getElementsByClassName("question_txt")[0].style.display = "none"; // Masquage de la div qui contient la question
    }
}

function deleteQuestion(event,id) {

    fetch(`/delete/${id}`, { method: 'DELETE' })
      .then(response => response.json()).then(data => {
          if (data.status !== 200){
              alert(data.message)
          }else {
              alert(data.message)
              event.target.closest('.question').remove();
          }
    })
      .catch(error => {
        console.error(error)
        alert('Erreur lors de la suppression de la question')
      })

}

function printDiv(divName) {
    let printContents = document.getElementById(divName).innerHTML;
    let originalContents = document.body.innerHTML;
    document.body.innerHTML = printContents;
    window.print();
    document.body.innerHTML = originalContents;
}