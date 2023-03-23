function ShowAndHideReponse(){
    if(document.getElementById('listeReponses').style.display == 'none' ) {
        document.getElementById('listeReponses').style.display = 'block';
    } else{
        document.getElementsByClassName(".arrow").rotate = -90;
        document.getElementById('listeReponses').style.display = 'none';
    }
}

function ShowAndHideQuestion(){
    if(document.getElementsByClassName('listeQuestion')[0].style.display == 'none'){
        document.getElementsByClassName('listeQuestion')[0].style.display = 'block';
    } else{
        document.getElementsByClassName('listeQuestion')[0].style.display = 'none';
    }
}
