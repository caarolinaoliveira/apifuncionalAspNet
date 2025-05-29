using System.Data.SqlTypes;
using System.Threading.Tasks;
using ApiFuncional.Data;
using ApiFuncional.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
namespace ApiFuncional.Controllers;

[ApiController]
[Route("api/produtos")]
public class ProdutosController : ControllerBase
{
    // aqui precisamos de contexto, injeção de dependência pelo construtor
    private readonly ApiDbContext _context;
    public ProdutosController(ApiDbContext context)
    {
        _context = context;
    }


    [HttpGet]
    public async Task<ActionResult<IEnumerable<Produto>>> GetProdutos()
    {
        if (_context.Produtos == null)
        {
            return NotFound();
        }

        return await _context.Produtos.ToListAsync();
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<Produto>> GetProdutoById(int id)
    {
        if (_context.Produtos == null)
        {
            return NotFound();
        }
        var produto = await _context.Produtos.FindAsync(id);

        if (produto == null)
        {
            return NotFound();
        }
        return produto;

    }

    [HttpPost]

    public async Task<ActionResult<Produto>> PostProduto(Produto produto)
    {
        if (_context.Produtos == null)
        {
            return Problem("Erro ao criar um produto, contate o suporte");
        }
        if (!ModelState.IsValid)
        {
            return ValidationProblem(new ValidationProblemDetails(ModelState)
            {
                Title = "Erro de validação",
                Detail = "Um ou mais erros de validação ocorreram."
            });
        }
        _context.Produtos.Add(produto);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetProdutoById), new { id = produto.Id }, produto);
    }

    [HttpPut("{id :int}")]
    public async Task<ActionResult> PutProduto(int id, Produto produto)
    {
        if (id != produto.Id) return BadRequest();
        if (!ModelState.IsValid) return ValidationProblem(ModelState);

        _context.Entry(produto).State = EntityState.Modified;

        try
        {
            await _context.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException)
        {
            if (!ProdutoExists(id))
            {
                return NotFound();
            }
            else
            {
                throw;
            }
        }

        return NoContent();
    }


    [HttpDelete("{id:int}")]
    public async Task<ActionResult> DeleteProduto(int id)
    {
        if (_context.Produtos == null)
        {
            return NotFound();
        }
        var produto = await _context.Produtos.FindAsync(id);
        if(produto == null)
        {
            return NotFound();
        }
        _context.Produtos.Remove(produto);
        
        await _context.SaveChangesAsync();

        return NoContent();

    }
    
    private bool ProdutoExists(int id)
    {
        return (_context.Produtos?.Any(e => e.Id == id)).GetValueOrDefault();
    }
}