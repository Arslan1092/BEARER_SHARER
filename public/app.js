const $ = s => document.querySelector(s);
const year = $('#year'); if (year) year.textContent = new Date().getFullYear();
const menu = $('.menu'); const links = $('.nav-links');
menu?.addEventListener('click', () => { links?.classList.toggle('open'); if (links?.classList.contains('open')) { links.style.display='flex'; links.style.position='absolute'; links.style.top='78px'; links.style.left='0'; links.style.right='0'; links.style.padding='20px'; links.style.background='#07181d'; links.style.flexDirection='column'; links.style.borderBottom='1px solid rgba(255,255,255,.1)'; } else links.removeAttribute('style'); });
const observer = new IntersectionObserver(entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('show'); observer.unobserve(e.target); } }), { threshold: .12 });
document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
const form = $('#contactForm');
form?.addEventListener('submit', async e => { e.preventDefault(); const status=$('#formStatus'); status.textContent='Sending...'; status.style.color='#a9b7bb'; try { const body=Object.fromEntries(new FormData(form)); const r=await fetch('/api/contact',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); const data=await r.json(); if(!r.ok) throw new Error(data.error||'Could not send message.'); form.reset(); status.textContent=data.message; status.style.color='#35d39b'; } catch(err){ status.textContent=err.message; status.style.color='#ff7b88'; }});
