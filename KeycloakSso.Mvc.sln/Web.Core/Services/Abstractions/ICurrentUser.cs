using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Web.Core.Services.Abstractions
{
    public interface ICurrentUser
    {
        string? Username { get; }
    }
}
