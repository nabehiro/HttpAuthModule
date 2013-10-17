using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace HttpAuthModule.SampleMvc.Controllers
{
    public class HomeController : Controller
    {
        public string Index()
        {
            return "Home-Index";
        }

        public string Ignore()
        {
            return "Home-Ignore";
        }
    }
}
