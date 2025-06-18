document.addEventListener('DOMContentLoaded',()=>{
  const studyCtx=document.getElementById('studyChart');
  if(studyCtx && window.weekData){
    new Chart(studyCtx,{
      type:'bar',
      data:{labels:['Pzt','Sal','Çar','Per','Cum','Cmt','Paz'],datasets:[{label:'Dakika',data:window.weekData,backgroundColor:'#6c7cd2'}]},
      options:{responsive:true,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true}}}
    });
  }
  const netCtx=document.getElementById('netChart');
  if(netCtx && window.netData){
    new Chart(netCtx,{
      type:'doughnut',
      data:{labels:['TYT','AYT'],datasets:[{data:window.netData,backgroundColor:['#28a745','#ffc107']} ]},
      options:{responsive:true,circumference:180,rotation:-90}
    });
  }
  if(window.AOS){AOS.init();}
}); 