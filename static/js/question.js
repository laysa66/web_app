//creer et modifier questions
window.onload = function () { // Quand la page est chargée
    document.getElementById("question").addEventListener("keydown", function (e) { // Gestion de l'indentation avec la touche tab de la zone de texte
        if (e.key === "Tab") { // Si la touche appuyée est la touche tab on ajoute une tabulation
            e.preventDefault();
            var start = this.selectionStart;
            var end = this.selectionEnd;
            this.value = this.value.substring(0, start) + "\t" + this.value.substring(end);
            this.selectionStart = this.selectionEnd = start + 1;
        }
    });
};

function previewQuestion() { // Fonction qui permet de prévisualiser la question
    document.getElementById("preview").style.display = "block"; // Affichage de la div qui contient la prévisualisation
    document.getElementById("question").style.display = "none"; // Masquage de la div qui contient la question
    document.getElementById("btn-preview").innerText = "Edition"; // Modification du texte du bouton
    document.getElementById("btn-preview").setAttribute("onclick", "backToEdit()"); // Modification de la fonction du bouton
    var question = document.getElementById("question").value; // Récupération de la question
    console.log("question: ", question);
    var preview = document.getElementById("preview"); // Récupération de la div qui contient la prévisualisation
    const renderer = new marked.Renderer(); // Création d'un nouveau renderer

    renderer.text = function (text) { // Fonction qui permet de gérer le rendu des $$...$$ et des $...$
        try {
            text = text.replace(/\$\$([^$]+)\$\$/g, function (match, p1) { // Fonction qui permet de gérer le rendu des $$...$$
                return katex.renderToString(p1, { displayMode: true });
            });
            text = text.replace(/\$([^$]+)\$/g, function (match, p1) { // Fonction qui permet de gérer le rendu des $...$
                return katex.renderToString(p1);
            });
            return text;
        }
        catch (e) {
            return text;
        }
    };
    console.log("renderer 1: ", renderer);
    renderer.code = function (code, language) { // Fonction qui permet de gérer le rendu des codes mermaid et des codes classiques
        if (language == "mermaid") {
            return `<div class="mermaid">${code}</div>`;
        }
        else {
            return `<pre><code class="hljs ${language}">${hljs.highlightAuto(code).value}</code></pre>`;
        }
    };
    console.log("renderer 2: ", renderer);
    if (hljs && hljs.highlightAuto) {
        console.log("hljs library is loaded");
    } else {
        console.log("hljs library is not loaded");
    }


    marked.setOptions({
        renderer: renderer,
        gfm: true,
        breaks: true,
        highlight: function (code, language) {
            if (language == "mermaid") {
                return code;
            }
            else if (language) {
                return hljs.highlight(code, { language: language }).value;
            }
            else {
                return hljs.highlightAuto(code).value;
            }
        }
    });
    preview.innerHTML = marked(question);
    console.log("preview: ", preview);
    mermaid.init();

}

function backToEdit() { // Fonction qui permet de revenir à l'édition de la question
    document.getElementById("preview").style.display = "none"; // Masquage de la div qui contient la prévisualisation
    document.getElementById("question").style.display = "block"; // Affichage de la div qui contient la question
    document.getElementById("btn-preview").innerText = "Aperçu"; // Modification du texte du bouton
    document.getElementById("btn-preview").setAttribute("onclick", "previewQuestion()"); // Modification de la fonction du bouton
}

